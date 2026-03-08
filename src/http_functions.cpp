#include "duckdb_extension.h"
#include "http_client_extension.hpp"
#include "http_config.hpp"
#include "lru_pool.hpp"
#include "negotiate_auth.hpp"
#include "rate_limiter.hpp"

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

DUCKDB_EXTENSION_EXTERN

namespace http_client {

// ---------------------------------------------------------------------------
// Global state: session pool and rate limiter registry
// ---------------------------------------------------------------------------

static LRUPool<std::string, cpr::Session> &GetSessionPool() {
	static LRUPool<std::string, cpr::Session> pool(50);
	return pool;
}

static RateLimiterRegistry &GetRateLimiterRegistry() {
	static RateLimiterRegistry registry(200);
	return registry;
}

// Stashed database handle from extension init, used to create connections for reading http_config
static duckdb_database g_database = nullptr;

void SetDatabase(duckdb_database db) {
	g_database = db;
}

// ---------------------------------------------------------------------------
// Helpers: extract MAP parameters, read config variable
// ---------------------------------------------------------------------------

//! Extract key-value pairs from a MAP(VARCHAR, VARCHAR) duckdb_value.
static std::vector<std::pair<std::string, std::string>> ExtractMapParam(duckdb_value map_val) {
	std::vector<std::pair<std::string, std::string>> result;
	if (!map_val) {
		return result;
	}
	idx_t size = duckdb_get_map_size(map_val);
	for (idx_t i = 0; i < size; i++) {
		duckdb_value key = duckdb_get_map_key(map_val, i);
		duckdb_value val = duckdb_get_map_value(map_val, i);
		char *key_str = duckdb_get_varchar(key);
		char *val_str = duckdb_get_varchar(val);
		if (key_str && val_str) {
			result.emplace_back(key_str, val_str);
		}
		if (key_str) {
			duckdb_free(key_str);
		}
		if (val_str) {
			duckdb_free(val_str);
		}
		duckdb_destroy_value(&key);
		duckdb_destroy_value(&val);
	}
	return result;
}

//! Read the http_config variable by opening a temporary connection.
//! Uses the chunk-based API (stable) rather than deprecated row-based accessors.
static std::vector<std::pair<std::string, std::string>> ReadHttpConfigVariable() {
	std::vector<std::pair<std::string, std::string>> entries;
	if (!g_database) {
		return entries;
	}

	duckdb_connection conn;
	if (duckdb_connect(g_database, &conn) == DuckDBError) {
		return entries;
	}

	duckdb_result result;
	// Try to read the variable; it may not be set
	auto state = duckdb_query(conn, "SELECT key, value FROM (SELECT unnest(map_keys(getvariable('http_config'))) AS key, "
	                                "unnest(map_values(getvariable('http_config'))) AS value)", &result);
	if (state == DuckDBError) {
		duckdb_destroy_result(&result);
		duckdb_disconnect(&conn);
		return entries;
	}

	// Fetch chunks until exhausted
	while (true) {
		duckdb_data_chunk chunk = duckdb_fetch_chunk(result);
		if (!chunk) {
			break;
		}
		idx_t chunk_size = duckdb_data_chunk_get_size(chunk);
		duckdb_vector key_vec = duckdb_data_chunk_get_vector(chunk, 0);
		duckdb_vector val_vec = duckdb_data_chunk_get_vector(chunk, 1);
		auto *key_data = (duckdb_string_t *)duckdb_vector_get_data(key_vec);
		auto *val_data = (duckdb_string_t *)duckdb_vector_get_data(val_vec);

		for (idx_t i = 0; i < chunk_size; i++) {
			auto key_str = duckdb_string_t_data(&key_data[i]);
			auto key_len = duckdb_string_t_length(key_data[i]);
			auto val_str = duckdb_string_t_data(&val_data[i]);
			auto val_len = duckdb_string_t_length(val_data[i]);
			entries.emplace_back(std::string(key_str, key_len), std::string(val_str, val_len));
		}
		duckdb_destroy_data_chunk(&chunk);
	}
	duckdb_destroy_result(&result);
	duckdb_disconnect(&conn);
	return entries;
}

//! Extract hostname from a URL (for rate limiter keying and session pooling).
static std::string ExtractHost(const std::string &url) {
	auto pos = url.find("://");
	if (pos == std::string::npos) {
		return url;
	}
	auto host_start = pos + 3;
	auto host_end = url.find_first_of(":/?#", host_start);
	if (host_end == std::string::npos) {
		host_end = url.length();
	}
	return url.substr(host_start, host_end - host_start);
}

//! Convert response headers to a JSON object string.
static std::string HeadersToJson(const cpr::Header &headers) {
	nlohmann::json j = nlohmann::json::object();
	for (auto &[key, value] : headers) {
		j[key] = value;
	}
	return j.dump();
}

// ---------------------------------------------------------------------------
// Bind data: holds parsed parameters for one table function invocation
// ---------------------------------------------------------------------------

struct HttpBindData {
	std::string method;
	std::string url;
	std::vector<std::pair<std::string, std::string>> headers;
	std::vector<std::pair<std::string, std::string>> params; // GET query params
	std::string body;
	std::string content_type;
	int timeout_override = -1; // -1 means use config
	int verify_ssl_override = -1; // -1 means use config, 0 = false, 1 = true
};

static void DestroyBindData(void *data) {
	delete static_cast<HttpBindData *>(data);
}

// ---------------------------------------------------------------------------
// Init data: tracks whether we've emitted the single result row
// ---------------------------------------------------------------------------

struct HttpInitData {
	bool done = false;
};

static void DestroyInitData(void *data) {
	delete static_cast<HttpInitData *>(data);
}

// ---------------------------------------------------------------------------
// Core: execute the HTTP request
// ---------------------------------------------------------------------------

struct HttpResult {
	std::string request_url;
	std::string request_method;
	std::string request_headers_json;
	std::string request_body;
	int response_status_code = 0;
	std::string response_status;
	std::string response_headers_json;
	std::string response_body;
	std::string response_url;
	double elapsed = 0.0;
	int redirect_count = 0;
};

static HttpResult ExecuteRequest(const HttpBindData &bind_data) {
	// Resolve config — variable reading is currently disabled because variables
	// are per-connection and we can't access the caller's connection from here.
	// Config comes from hard-coded defaults + per-call overrides for now.
	HttpConfig config;

	// Apply per-call timeout override
	int timeout = (bind_data.timeout_override >= 0) ? bind_data.timeout_override : config.timeout;

	auto host = ExtractHost(bind_data.url);

	// Rate limiting: wait if needed
	auto *limiter = GetRateLimiterRegistry().GetOrCreate(host, config.rate_limit_spec, config.burst);
	if (limiter) {
		int max_retries = 50;
		while (!limiter->TryAcquire() && max_retries-- > 0) {
			double wait = limiter->WaitTime();
			if (wait > 0.0) {
				std::this_thread::sleep_for(std::chrono::duration<double>(wait));
			}
		}
	}

	// Build the cpr request
	cpr::Url cpr_url{bind_data.url};
	cpr::Header cpr_headers;
	for (auto &[k, v] : bind_data.headers) {
		cpr_headers[k] = v;
	}

	// Apply auth from config
	if (config.auth_type == "negotiate" && cpr_headers.find("Authorization") == cpr_headers.end()) {
		try {
			auto neg_result = GenerateNegotiateToken(bind_data.url);
			cpr_headers["Authorization"] = "Negotiate " + neg_result.token;
		} catch (...) {
			// If negotiate fails (no ticket, wrong URL scheme), proceed without it
		}
	} else if (config.auth_type == "bearer" && !config.bearer_token.empty() &&
	           cpr_headers.find("Authorization") == cpr_headers.end()) {
		cpr_headers["Authorization"] = "Bearer " + config.bearer_token;
	}

	// Content-Type for POST/PUT/PATCH
	auto content_type = bind_data.content_type;
	if (!bind_data.body.empty() && content_type.empty()) {
		content_type = "application/json";
	}
	if (!content_type.empty()) {
		cpr_headers["Content-Type"] = content_type;
	}

	// Build session
	cpr::Session session;
	session.SetUrl(cpr_url);
	session.SetHeader(cpr_headers);
	session.SetTimeout(cpr::Timeout{timeout * 1000});

	bool verify_ssl = (bind_data.verify_ssl_override >= 0) ? (bind_data.verify_ssl_override == 1) : config.verify_ssl;
	if (!verify_ssl) {
		session.SetVerifySsl(cpr::VerifySsl{false});
	}
	if (!config.ca_bundle.empty()) {
		cpr::SslOptions ssl_opts;
		ssl_opts.SetOption(cpr::ssl::CaInfo{config.ca_bundle});
		session.SetSslOptions(ssl_opts);
	}
	if (!config.proxy.empty()) {
		session.SetProxies(cpr::Proxies{{"http", config.proxy}, {"https", config.proxy}});
	}

	// Query params (for GET)
	if (!bind_data.params.empty()) {
		cpr::Parameters cpr_params;
		for (auto &[k, v] : bind_data.params) {
			cpr_params.Add(cpr::Parameter{k, v});
		}
		session.SetParameters(cpr_params);
	}

	// Body (for POST/PUT/PATCH)
	if (!bind_data.body.empty()) {
		session.SetBody(cpr::Body{bind_data.body});
	}

	// Execute the appropriate method
	cpr::Response response;
	auto method = bind_data.method;
	if (method == "GET") {
		response = session.Get();
	} else if (method == "POST") {
		response = session.Post();
	} else if (method == "PUT") {
		response = session.Put();
	} else if (method == "DELETE") {
		response = session.Delete();
	} else if (method == "PATCH") {
		response = session.Patch();
	} else if (method == "HEAD") {
		response = session.Head();
	} else if (method == "OPTIONS") {
		response = session.Options();
	} else {
		throw std::runtime_error("Unsupported HTTP method: " + method);
	}

	// Build result
	HttpResult result;
	result.request_url = bind_data.url;
	result.request_method = method;

	nlohmann::json req_headers_json = nlohmann::json::object();
	for (auto &[k, v] : cpr_headers) {
		req_headers_json[k] = v;
	}
	result.request_headers_json = req_headers_json.dump();
	result.request_body = bind_data.body;

	result.response_status_code = static_cast<int>(response.status_code);
	result.response_status = response.status_line;
	result.response_headers_json = HeadersToJson(response.header);
	result.response_body = response.text;
	result.response_url = response.url.str();
	result.elapsed = response.elapsed;
	result.redirect_count = static_cast<int>(response.redirect_count);

	return result;
}

// ---------------------------------------------------------------------------
// Table function callbacks
// ---------------------------------------------------------------------------

//! Shared bind for all HTTP methods. Method is stored in extra_info.
static void HttpBind(duckdb_bind_info info) {
	auto *bind_data = new HttpBindData();
	// Get the method from extra_info
	auto *method = static_cast<const char *>(duckdb_bind_get_extra_info(info));
	bind_data->method = method;

	// First positional parameter is always the URL
	duckdb_value url_val = duckdb_bind_get_parameter(info, 0);
	char *url_str = duckdb_get_varchar(url_val);
	if (url_str) {
		bind_data->url = url_str;
		duckdb_free(url_str);
	}
	duckdb_destroy_value(&url_val);

	if (bind_data->url.empty()) {
		duckdb_bind_set_error(info, "URL parameter is required");
		delete bind_data;
		return;
	}

	// For http_do, the first param is method, second is URL
	if (std::string(method) == "DO") {
		bind_data->method = bind_data->url; // first param was actually the method
		// Convert to uppercase
		for (auto &c : bind_data->method) {
			c = toupper(c);
		}
		duckdb_value url_val2 = duckdb_bind_get_parameter(info, 1);
		char *url_str2 = duckdb_get_varchar(url_val2);
		if (url_str2) {
			bind_data->url = url_str2;
			duckdb_free(url_str2);
		}
		duckdb_destroy_value(&url_val2);
	}

	// Named parameters
	duckdb_value headers_val = duckdb_bind_get_named_parameter(info, "headers");
	if (headers_val) {
		bind_data->headers = ExtractMapParam(headers_val);
		duckdb_destroy_value(&headers_val);
	}

	duckdb_value params_val = duckdb_bind_get_named_parameter(info, "params");
	if (params_val) {
		bind_data->params = ExtractMapParam(params_val);
		duckdb_destroy_value(&params_val);
	}

	duckdb_value body_val = duckdb_bind_get_named_parameter(info, "body");
	if (body_val) {
		char *body_str = duckdb_get_varchar(body_val);
		if (body_str) {
			bind_data->body = body_str;
			duckdb_free(body_str);
		}
		duckdb_destroy_value(&body_val);
	}

	duckdb_value ct_val = duckdb_bind_get_named_parameter(info, "content_type");
	if (ct_val) {
		char *ct_str = duckdb_get_varchar(ct_val);
		if (ct_str) {
			bind_data->content_type = ct_str;
			duckdb_free(ct_str);
		}
		duckdb_destroy_value(&ct_val);
	}

	duckdb_value timeout_val = duckdb_bind_get_named_parameter(info, "timeout");
	if (timeout_val) {
		bind_data->timeout_override = static_cast<int>(duckdb_get_int64(timeout_val));
		duckdb_destroy_value(&timeout_val);
	}

	duckdb_value verify_ssl_val = duckdb_bind_get_named_parameter(info, "verify_ssl");
	if (verify_ssl_val) {
		bind_data->verify_ssl_override = duckdb_get_bool(verify_ssl_val) ? 1 : 0;
		duckdb_destroy_value(&verify_ssl_val);
	}

	// Define output columns
	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type int_type = duckdb_create_logical_type(DUCKDB_TYPE_INTEGER);
	duckdb_logical_type double_type = duckdb_create_logical_type(DUCKDB_TYPE_DOUBLE);

	duckdb_bind_add_result_column(info, "request_url", varchar_type);
	duckdb_bind_add_result_column(info, "request_method", varchar_type);
	duckdb_bind_add_result_column(info, "request_headers", varchar_type);
	duckdb_bind_add_result_column(info, "request_body", varchar_type);
	duckdb_bind_add_result_column(info, "response_status_code", int_type);
	duckdb_bind_add_result_column(info, "response_status", varchar_type);
	duckdb_bind_add_result_column(info, "response_headers", varchar_type);
	duckdb_bind_add_result_column(info, "response_body", varchar_type);
	duckdb_bind_add_result_column(info, "response_url", varchar_type);
	duckdb_bind_add_result_column(info, "elapsed", double_type);
	duckdb_bind_add_result_column(info, "redirect_count", int_type);

	duckdb_destroy_logical_type(&varchar_type);
	duckdb_destroy_logical_type(&int_type);
	duckdb_destroy_logical_type(&double_type);

	duckdb_bind_set_cardinality(info, 1, true);
	duckdb_bind_set_bind_data(info, bind_data, DestroyBindData);
}

static void HttpInit(duckdb_init_info info) {
	auto *init_data = new HttpInitData();
	duckdb_init_set_init_data(info, init_data, DestroyInitData);
	duckdb_init_set_max_threads(info, 1);
}

static void HttpExecute(duckdb_function_info info, duckdb_data_chunk output) {
	auto *init_data = static_cast<HttpInitData *>(duckdb_function_get_init_data(info));
	auto *bind_data = static_cast<HttpBindData *>(duckdb_function_get_bind_data(info));

	if (init_data->done) {
		duckdb_data_chunk_set_size(output, 0);
		return;
	}

	HttpResult result;
	try {
		result = ExecuteRequest(*bind_data);
	} catch (const std::exception &e) {
		duckdb_function_set_error(info, e.what());
		return;
	}

	duckdb_data_chunk_set_size(output, 1);

	// Helper to set a varchar column
	auto set_varchar = [&](idx_t col, const std::string &val) {
		duckdb_vector vec = duckdb_data_chunk_get_vector(output, col);
		duckdb_vector_assign_string_element_len(vec, 0, val.c_str(), val.length());
	};
	auto set_int = [&](idx_t col, int val) {
		duckdb_vector vec = duckdb_data_chunk_get_vector(output, col);
		auto *data = (int32_t *)duckdb_vector_get_data(vec);
		data[0] = val;
	};
	auto set_double = [&](idx_t col, double val) {
		duckdb_vector vec = duckdb_data_chunk_get_vector(output, col);
		auto *data = (double *)duckdb_vector_get_data(vec);
		data[0] = val;
	};

	set_varchar(0, result.request_url);
	set_varchar(1, result.request_method);
	set_varchar(2, result.request_headers_json);
	set_varchar(3, result.request_body);
	set_int(4, result.response_status_code);
	set_varchar(5, result.response_status);
	set_varchar(6, result.response_headers_json);
	set_varchar(7, result.response_body);
	set_varchar(8, result.response_url);
	set_double(9, result.elapsed);
	set_int(10, result.redirect_count);

	init_data->done = true;
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

//! Register a table function for a specific HTTP method.
//! For http_do, method should be "DO" and an extra positional param is added.
static void RegisterHttpMethod(duckdb_connection connection, const char *name, const char *method, bool has_body) {
	duckdb_table_function function = duckdb_create_table_function();
	duckdb_table_function_set_name(function, name);

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type int_type = duckdb_create_logical_type(DUCKDB_TYPE_INTEGER);
	duckdb_logical_type map_type = duckdb_create_map_type(varchar_type, varchar_type);

	// Positional params
	if (std::string(method) == "DO") {
		duckdb_table_function_add_parameter(function, varchar_type); // method
	}
	duckdb_table_function_add_parameter(function, varchar_type); // url

	// Named params — all optional
	duckdb_table_function_add_named_parameter(function, "headers", map_type);
	duckdb_table_function_add_named_parameter(function, "params", map_type);
	if (has_body || std::string(method) == "DO") {
		duckdb_table_function_add_named_parameter(function, "body", varchar_type);
		duckdb_table_function_add_named_parameter(function, "content_type", varchar_type);
	}
	duckdb_table_function_add_named_parameter(function, "timeout", int_type);

	duckdb_logical_type bool_type = duckdb_create_logical_type(DUCKDB_TYPE_BOOLEAN);
	duckdb_table_function_add_named_parameter(function, "verify_ssl", bool_type);
	duckdb_destroy_logical_type(&bool_type);

	duckdb_destroy_logical_type(&varchar_type);
	duckdb_destroy_logical_type(&int_type);
	duckdb_destroy_logical_type(&map_type);

	// Store the method name as extra_info (static string, no cleanup needed)
	duckdb_table_function_set_extra_info(function, (void *)method, nullptr);

	duckdb_table_function_set_bind(function, HttpBind);
	duckdb_table_function_set_init(function, HttpInit);
	duckdb_table_function_set_function(function, HttpExecute);

	duckdb_register_table_function(connection, function);
	duckdb_destroy_table_function(&function);
}

// ---------------------------------------------------------------------------
// Scalar function: http_request(method, url, headers_json, body, content_type)
// Returns a JSON string with the full request/response envelope.
// All parameters are VARCHAR. headers_json is a JSON object string.
// This variant works in any expression context including JOINs.
// ---------------------------------------------------------------------------

//! Parse a JSON object string into key-value pairs. Returns empty on null/invalid.
static std::vector<std::pair<std::string, std::string>> ParseJsonObject(const char *str, size_t len) {
	std::vector<std::pair<std::string, std::string>> result;
	if (!str || len == 0) {
		return result;
	}
	try {
		auto j = nlohmann::json::parse(std::string(str, len));
		if (j.is_object()) {
			for (auto &[key, val] : j.items()) {
				result.emplace_back(key, val.is_string() ? val.get<std::string>() : val.dump());
			}
		}
	} catch (...) {
		// Malformed JSON — return empty
	}
	return result;
}

//! Helper to read a VARCHAR vector element, returning empty string if null.
static std::string ReadVarchar(duckdb_vector vec, uint64_t *validity, idx_t row) {
	if (validity && !(validity[row / 64] & (1ULL << (row % 64)))) {
		return "";
	}
	auto *data = (duckdb_string_t *)duckdb_vector_get_data(vec);
	auto str = duckdb_string_t_data(&data[row]);
	auto len = duckdb_string_t_length(data[row]);
	return std::string(str, len);
}

static void HttpRequestScalarFunc(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t input_size = duckdb_data_chunk_get_size(input);

	duckdb_vector method_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector url_vec = duckdb_data_chunk_get_vector(input, 1);
	duckdb_vector headers_vec = duckdb_data_chunk_get_vector(input, 2);
	duckdb_vector body_vec = duckdb_data_chunk_get_vector(input, 3);
	duckdb_vector ct_vec = duckdb_data_chunk_get_vector(input, 4);

	auto *method_validity = duckdb_vector_get_validity(method_vec);
	auto *url_validity = duckdb_vector_get_validity(url_vec);
	auto *headers_validity = duckdb_vector_get_validity(headers_vec);
	auto *body_validity = duckdb_vector_get_validity(body_vec);
	auto *ct_validity = duckdb_vector_get_validity(ct_vec);

	for (idx_t row = 0; row < input_size; row++) {
		auto method = ReadVarchar(method_vec, method_validity, row);
		auto url = ReadVarchar(url_vec, url_validity, row);

		if (method.empty() || url.empty()) {
			duckdb_scalar_function_set_error(info, "method and url are required");
			return;
		}

		// Uppercase the method
		for (auto &c : method) {
			c = toupper(c);
		}

		// Parse optional JSON headers
		auto headers_str = ReadVarchar(headers_vec, headers_validity, row);
		auto body = ReadVarchar(body_vec, body_validity, row);
		auto content_type = ReadVarchar(ct_vec, ct_validity, row);

		HttpBindData bind_data;
		bind_data.method = method;
		bind_data.url = url;
		bind_data.headers = ParseJsonObject(headers_str.c_str(), headers_str.size());
		bind_data.body = body;
		bind_data.content_type = content_type;

		HttpResult result;
		try {
			result = ExecuteRequest(bind_data);
		} catch (const std::exception &e) {
			duckdb_scalar_function_set_error(info, e.what());
			return;
		}

		// Build JSON response envelope
		nlohmann::json j;
		j["request_url"] = result.request_url;
		j["request_method"] = result.request_method;
		j["request_headers"] = nlohmann::json::parse(result.request_headers_json);
		j["request_body"] = result.request_body;
		j["response_status_code"] = result.response_status_code;
		j["response_status"] = result.response_status;
		j["response_headers"] = nlohmann::json::parse(result.response_headers_json);
		j["response_body"] = result.response_body;
		j["response_url"] = result.response_url;
		j["elapsed"] = result.elapsed;
		j["redirect_count"] = result.redirect_count;

		auto json_str = j.dump();
		duckdb_vector_assign_string_element_len(output, row, json_str.c_str(), json_str.length());
	}
}

static void RegisterHttpRequestScalar(duckdb_connection connection) {
	duckdb_scalar_function function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(function, "http_request");

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);

	// http_request(method, url, headers_json, body, content_type)
	duckdb_scalar_function_add_parameter(function, varchar_type);  // method
	duckdb_scalar_function_add_parameter(function, varchar_type);  // url
	duckdb_scalar_function_add_parameter(function, varchar_type);  // headers (JSON string)
	duckdb_scalar_function_add_parameter(function, varchar_type);  // body
	duckdb_scalar_function_add_parameter(function, varchar_type);  // content_type

	duckdb_scalar_function_set_return_type(function, varchar_type);
	duckdb_destroy_logical_type(&varchar_type);

	duckdb_scalar_function_set_function(function, HttpRequestScalarFunc);
	duckdb_scalar_function_set_special_handling(function);

	duckdb_register_scalar_function(connection, function);
	duckdb_destroy_scalar_function(&function);
}

// ---------------------------------------------------------------------------
// Register everything
// ---------------------------------------------------------------------------

void RegisterHttpFunctions(duckdb_connection connection) {
	// Table functions (for interactive/literal use)
	RegisterHttpMethod(connection, "http_get", "GET", false);
	RegisterHttpMethod(connection, "http_post", "POST", true);
	RegisterHttpMethod(connection, "http_put", "PUT", true);
	RegisterHttpMethod(connection, "http_delete", "DELETE", false);
	RegisterHttpMethod(connection, "http_patch", "PATCH", true);
	RegisterHttpMethod(connection, "http_head", "HEAD", false);
	RegisterHttpMethod(connection, "http_options", "OPTIONS", false);
	RegisterHttpMethod(connection, "http_do", "DO", true);

	// Scalar function (for data-driven/JOIN use)
	RegisterHttpRequestScalar(connection);
}

} // namespace http_client
