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

//! Global rate limiter — caps total outbound requests/second across all hosts.
//! Lazily initialized on first use; re-created if the spec changes.
static std::mutex g_global_limiter_mutex;
static std::unique_ptr<GCRARateLimiter> g_global_limiter;
static std::string g_global_limiter_spec;

//! Get or (re)create the global rate limiter. Returns nullptr if no global limit is configured.
static GCRARateLimiter *GetGlobalLimiter(const std::string &spec, double burst) {
	if (spec.empty()) {
		return nullptr;
	}
	std::lock_guard<std::mutex> lock(g_global_limiter_mutex);
	if (!g_global_limiter || g_global_limiter_spec != spec) {
		double rate = ParseRateLimit(spec);
		g_global_limiter = std::make_unique<GCRARateLimiter>(rate, burst, spec);
		g_global_limiter_spec = spec;
	}
	return g_global_limiter.get();
}

//! Snapshot the global limiter for diagnostics (returns nullptr if not configured).
static GCRARateLimiter *GetGlobalLimiterSnapshot() {
	std::lock_guard<std::mutex> lock(g_global_limiter_mutex);
	return g_global_limiter.get();
}

// ---------------------------------------------------------------------------
// Helpers
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
	int timeout_override = -1;    // -1 means use config
	int verify_ssl_override = -1; // -1 means use config, 0 = false, 1 = true
	// Config entries from the SQL macro layer (read from getvariable in caller's context)
	std::vector<std::pair<std::string, std::string>> config_entries;
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
// Core: build sessions and execute HTTP requests
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

//! Map a method string to cpr::MultiPerform::HttpMethod.
static cpr::MultiPerform::HttpMethod ToCprMethod(const std::string &method) {
	if (method == "GET") return cpr::MultiPerform::HttpMethod::GET_REQUEST;
	if (method == "POST") return cpr::MultiPerform::HttpMethod::POST_REQUEST;
	if (method == "PUT") return cpr::MultiPerform::HttpMethod::PUT_REQUEST;
	if (method == "DELETE") return cpr::MultiPerform::HttpMethod::DELETE_REQUEST;
	if (method == "PATCH") return cpr::MultiPerform::HttpMethod::PATCH_REQUEST;
	if (method == "HEAD") return cpr::MultiPerform::HttpMethod::HEAD_REQUEST;
	if (method == "OPTIONS") return cpr::MultiPerform::HttpMethod::OPTIONS_REQUEST;
	throw std::runtime_error("Unsupported HTTP method: " + method);
}

//! Build a configured cpr::Session from bind data and resolved config.
//! Returns the session (as shared_ptr for MultiPerform) and the headers used (for result building).
static std::pair<std::shared_ptr<cpr::Session>, cpr::Header>
BuildSession(const HttpBindData &bind_data, const HttpConfig &config) {
	int timeout = (bind_data.timeout_override >= 0) ? bind_data.timeout_override : config.timeout;

	auto session = std::make_shared<cpr::Session>();
	session->SetUrl(cpr::Url{bind_data.url});
	session->SetTimeout(cpr::Timeout{timeout * 1000});

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
		}
	} else if (config.auth_type == "bearer" && !config.bearer_token.empty() &&
	           cpr_headers.find("Authorization") == cpr_headers.end()) {
		cpr_headers["Authorization"] = "Bearer " + config.bearer_token;
	}

	auto content_type = bind_data.content_type;
	if (!bind_data.body.empty() && content_type.empty()) {
		content_type = "application/json";
	}
	if (!content_type.empty()) {
		cpr_headers["Content-Type"] = content_type;
	}

	session->SetHeader(cpr_headers);

	bool verify_ssl = (bind_data.verify_ssl_override >= 0) ? (bind_data.verify_ssl_override == 1) : config.verify_ssl;
	if (!verify_ssl) {
		session->SetVerifySsl(cpr::VerifySsl{false});
	}
	if (!config.ca_bundle.empty()) {
		cpr::SslOptions ssl_opts;
		ssl_opts.SetOption(cpr::ssl::CaInfo{config.ca_bundle});
		session->SetSslOptions(ssl_opts);
	}
	if (!config.proxy.empty()) {
		session->SetProxies(cpr::Proxies{{"http", config.proxy}, {"https", config.proxy}});
	}

	if (!bind_data.params.empty()) {
		cpr::Parameters cpr_params;
		for (auto &[k, v] : bind_data.params) {
			cpr_params.Add(cpr::Parameter{k, v});
		}
		session->SetParameters(cpr_params);
	}

	if (!bind_data.body.empty()) {
		session->SetBody(cpr::Body{bind_data.body});
	}

	return {session, cpr_headers};
}

//! Convert a cpr::Response into an HttpResult.
static HttpResult ResponseToResult(const cpr::Response &response, const HttpBindData &bind_data,
                                   const cpr::Header &req_headers) {
	HttpResult result;
	result.request_url = bind_data.url;
	result.request_method = bind_data.method;

	nlohmann::json req_headers_json = nlohmann::json::object();
	for (auto &[k, v] : req_headers) {
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

//! Acquire a rate limit token from the given limiter, sleeping if necessary.
//! Records pacing stats on the limiter.
static void AcquireRateLimit(GCRARateLimiter *limiter) {
	if (!limiter) return;
	int max_retries = 50;
	bool was_paced = false;
	double total_pacing = 0.0;
	while (!limiter->TryAcquire() && max_retries-- > 0) {
		double wait = limiter->WaitTime();
		if (wait > 0.0) {
			was_paced = true;
			total_pacing += wait;
			std::this_thread::sleep_for(std::chrono::duration<double>(wait));
		}
	}
	limiter->RecordRequest();
	if (was_paced) {
		limiter->RecordPacing(total_pacing);
	}
}

//! Record response facts and handle 429 feedback.
static void RecordResponseStats(const cpr::Response &response, const std::string &host) {
	auto *limiter = GetRateLimiterRegistry().GetOrCreate(host);
	if (!limiter) return;

	limiter->RecordResponse(response.elapsed, response.text.size(),
	                        static_cast<int>(response.status_code));

	if (response.status_code == 429) {
		double retry_after = 1.0;
		auto it = response.header.find("Retry-After");
		if (it != response.header.end()) {
			try { retry_after = std::stod(it->second); } catch (...) {}
		}
		limiter->RecordThrottle(retry_after);
	}

	// Record on the global limiter too, if active
	auto *global = GetGlobalLimiterSnapshot();
	if (global) {
		global->RecordResponse(response.elapsed, response.text.size(),
		                       static_cast<int>(response.status_code));
	}
}

//! Execute a single HTTP request (used by table functions).
//! Handles rate limiting, session building, execution, and 429 feedback.
static HttpResult ExecuteRequest(const HttpBindData &bind_data) {
	HttpConfig config = ResolveConfig(bind_data.url, bind_data.config_entries);
	auto host = ExtractHost(bind_data.url);

	// Rate limiting: global first, then per-host
	AcquireRateLimit(GetGlobalLimiter(config.global_rate_limit_spec, config.global_burst));
	AcquireRateLimit(GetRateLimiterRegistry().GetOrCreate(host, config.rate_limit_spec, config.burst));

	auto [session, req_headers] = BuildSession(bind_data, config);

	// Execute
	cpr::Response response;
	auto method = bind_data.method;
	if (method == "GET") { response = session->Get(); }
	else if (method == "POST") { response = session->Post(); }
	else if (method == "PUT") { response = session->Put(); }
	else if (method == "DELETE") { response = session->Delete(); }
	else if (method == "PATCH") { response = session->Patch(); }
	else if (method == "HEAD") { response = session->Head(); }
	else if (method == "OPTIONS") { response = session->Options(); }
	else { throw std::runtime_error("Unsupported HTTP method: " + method); }

	RecordResponseStats(response, host);
	return ResponseToResult(response, bind_data, req_headers);
}

// ---------------------------------------------------------------------------
// Table function callbacks
// ---------------------------------------------------------------------------

//! Bind for the unified _http_raw table function.
//! Positional: method (VARCHAR), url (VARCHAR)
//! Named: headers, params, body, content_type, timeout, verify_ssl, _config
static void HttpRawBind(duckdb_bind_info info) {
	auto *bind_data = new HttpBindData();

	// Positional param 0: method
	duckdb_value method_val = duckdb_bind_get_parameter(info, 0);
	char *method_str = duckdb_get_varchar(method_val);
	if (method_str) {
		bind_data->method = method_str;
		for (auto &c : bind_data->method) {
			c = toupper(c);
		}
		duckdb_free(method_str);
	}
	duckdb_destroy_value(&method_val);

	// Positional param 1: url
	duckdb_value url_val = duckdb_bind_get_parameter(info, 1);
	char *url_str = duckdb_get_varchar(url_val);
	if (url_str) {
		bind_data->url = url_str;
		duckdb_free(url_str);
	}
	duckdb_destroy_value(&url_val);

	if (bind_data->method.empty()) {
		duckdb_bind_set_error(info, "method parameter is required");
		delete bind_data;
		return;
	}
	if (bind_data->url.empty()) {
		duckdb_bind_set_error(info, "URL parameter is required");
		delete bind_data;
		return;
	}

	// Named parameters (all may be NULL when passed from macros with default := NULL)
	duckdb_value headers_val = duckdb_bind_get_named_parameter(info, "headers");
	if (headers_val) {
		if (!duckdb_is_null_value(headers_val)) {
			bind_data->headers = ExtractMapParam(headers_val);
		}
		duckdb_destroy_value(&headers_val);
	}

	duckdb_value params_val = duckdb_bind_get_named_parameter(info, "params");
	if (params_val) {
		if (!duckdb_is_null_value(params_val)) {
			bind_data->params = ExtractMapParam(params_val);
		}
		duckdb_destroy_value(&params_val);
	}

	duckdb_value body_val = duckdb_bind_get_named_parameter(info, "body");
	if (body_val) {
		if (!duckdb_is_null_value(body_val)) {
			char *body_str = duckdb_get_varchar(body_val);
			if (body_str) {
				bind_data->body = body_str;
				duckdb_free(body_str);
			}
		}
		duckdb_destroy_value(&body_val);
	}

	duckdb_value ct_val = duckdb_bind_get_named_parameter(info, "content_type");
	if (ct_val) {
		if (!duckdb_is_null_value(ct_val)) {
			char *ct_str = duckdb_get_varchar(ct_val);
			if (ct_str) {
				bind_data->content_type = ct_str;
				duckdb_free(ct_str);
			}
		}
		duckdb_destroy_value(&ct_val);
	}

	duckdb_value timeout_val = duckdb_bind_get_named_parameter(info, "timeout");
	if (timeout_val) {
		if (!duckdb_is_null_value(timeout_val)) {
			bind_data->timeout_override = static_cast<int>(duckdb_get_int64(timeout_val));
		}
		duckdb_destroy_value(&timeout_val);
	}

	duckdb_value verify_ssl_val = duckdb_bind_get_named_parameter(info, "verify_ssl");
	if (verify_ssl_val) {
		if (!duckdb_is_null_value(verify_ssl_val)) {
			bind_data->verify_ssl_override = duckdb_get_bool(verify_ssl_val) ? 1 : 0;
		}
		duckdb_destroy_value(&verify_ssl_val);
	}

	// _config: MAP(VARCHAR, VARCHAR) passed in by the SQL macro layer
	duckdb_value config_val = duckdb_bind_get_named_parameter(info, "_config");
	if (config_val) {
		if (!duckdb_is_null_value(config_val)) {
			bind_data->config_entries = ExtractMapParam(config_val);
		}
		duckdb_destroy_value(&config_val);
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
// Raw table function registration: _http_raw(method, url, ...)
// ---------------------------------------------------------------------------

static void RegisterHttpRawTableFunction(duckdb_connection connection) {
	duckdb_table_function function = duckdb_create_table_function();
	duckdb_table_function_set_name(function, "_http_raw");

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type int_type = duckdb_create_logical_type(DUCKDB_TYPE_INTEGER);
	duckdb_logical_type bool_type = duckdb_create_logical_type(DUCKDB_TYPE_BOOLEAN);
	duckdb_logical_type map_type = duckdb_create_map_type(varchar_type, varchar_type);

	// Positional: method, url
	duckdb_table_function_add_parameter(function, varchar_type); // method
	duckdb_table_function_add_parameter(function, varchar_type); // url

	// Named parameters
	duckdb_table_function_add_named_parameter(function, "headers", map_type);
	duckdb_table_function_add_named_parameter(function, "params", map_type);
	duckdb_table_function_add_named_parameter(function, "body", varchar_type);
	duckdb_table_function_add_named_parameter(function, "content_type", varchar_type);
	duckdb_table_function_add_named_parameter(function, "timeout", int_type);
	duckdb_table_function_add_named_parameter(function, "verify_ssl", bool_type);
	duckdb_table_function_add_named_parameter(function, "_config", map_type);

	duckdb_destroy_logical_type(&varchar_type);
	duckdb_destroy_logical_type(&int_type);
	duckdb_destroy_logical_type(&bool_type);
	duckdb_destroy_logical_type(&map_type);

	duckdb_table_function_set_bind(function, HttpRawBind);
	duckdb_table_function_set_init(function, HttpInit);
	duckdb_table_function_set_function(function, HttpExecute);

	duckdb_register_table_function(connection, function);
	duckdb_destroy_table_function(&function);
}

// ---------------------------------------------------------------------------
// Scalar function: _http_raw_request(method, url, headers_json, body,
//                                    content_type, config_json)
// Returns a JSON string with the full request/response envelope.
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

//! Write an HttpResult into the struct output vector at the given row index.
static void WriteResultToStruct(duckdb_vector output, idx_t row, const HttpResult &result) {
	auto set_varchar = [&](idx_t col, const std::string &val) {
		duckdb_vector vec = duckdb_struct_vector_get_child(output, col);
		duckdb_vector_assign_string_element_len(vec, row, val.c_str(), val.length());
	};
	auto set_int = [&](idx_t col, int val) {
		duckdb_vector vec = duckdb_struct_vector_get_child(output, col);
		auto *data = (int32_t *)duckdb_vector_get_data(vec);
		data[row] = val;
	};
	auto set_double = [&](idx_t col, double val) {
		duckdb_vector vec = duckdb_struct_vector_get_child(output, col);
		auto *data = (double *)duckdb_vector_get_data(vec);
		data[row] = val;
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
}

static void HttpRawRequestScalarFunc(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t input_size = duckdb_data_chunk_get_size(input);
	if (input_size == 0) return;

	duckdb_vector method_vec = duckdb_data_chunk_get_vector(input, 0);
	duckdb_vector url_vec = duckdb_data_chunk_get_vector(input, 1);
	duckdb_vector headers_vec = duckdb_data_chunk_get_vector(input, 2);
	duckdb_vector body_vec = duckdb_data_chunk_get_vector(input, 3);
	duckdb_vector ct_vec = duckdb_data_chunk_get_vector(input, 4);
	duckdb_vector config_vec = duckdb_data_chunk_get_vector(input, 5);

	auto *method_validity = duckdb_vector_get_validity(method_vec);
	auto *url_validity = duckdb_vector_get_validity(url_vec);
	auto *headers_validity = duckdb_vector_get_validity(headers_vec);
	auto *body_validity = duckdb_vector_get_validity(body_vec);
	auto *ct_validity = duckdb_vector_get_validity(ct_vec);
	auto *config_validity = duckdb_vector_get_validity(config_vec);

	// --- Phase 1: Parse all rows into bind data and resolve configs ---
	struct RowRequest {
		HttpBindData bind_data;
		HttpConfig config;
		std::string host;
		std::shared_ptr<cpr::Session> session;
		cpr::Header req_headers;
		cpr::MultiPerform::HttpMethod cpr_method;
	};
	std::vector<RowRequest> rows(input_size);

	int max_concurrent = 10; // default; will be overridden by first row's config

	for (idx_t row = 0; row < input_size; row++) {
		auto method = ReadVarchar(method_vec, method_validity, row);
		auto url = ReadVarchar(url_vec, url_validity, row);

		if (method.empty() || url.empty()) {
			duckdb_scalar_function_set_error(info, "method and url are required");
			return;
		}

		for (auto &c : method) {
			c = toupper(c);
		}

		auto headers_str = ReadVarchar(headers_vec, headers_validity, row);
		auto body = ReadVarchar(body_vec, body_validity, row);
		auto content_type = ReadVarchar(ct_vec, ct_validity, row);
		auto config_json = ReadVarchar(config_vec, config_validity, row);

		auto &req = rows[row];
		req.bind_data.method = method;
		req.bind_data.url = url;
		req.bind_data.headers = ParseJsonObject(headers_str.c_str(), headers_str.size());
		req.bind_data.body = body;
		req.bind_data.content_type = content_type;
		req.bind_data.config_entries = ParseJsonObject(config_json.c_str(), config_json.size());

		req.config = ResolveConfig(url, req.bind_data.config_entries);
		req.host = ExtractHost(url);

		try {
			req.cpr_method = ToCprMethod(method);
			auto [session, headers] = BuildSession(req.bind_data, req.config);
			req.session = session;
			req.req_headers = headers;
		} catch (const std::exception &e) {
			duckdb_scalar_function_set_error(info, e.what());
			return;
		}

		if (row == 0) {
			max_concurrent = req.config.max_concurrent;
		}
	}

	// --- Phase 2: Execute in batches using MultiPerform ---
	// Process in sub-batches of max_concurrent, rate-limiting between batches.
	std::vector<HttpResult> results(input_size);

	for (idx_t batch_start = 0; batch_start < input_size; batch_start += max_concurrent) {
		idx_t batch_end = std::min(batch_start + (idx_t)max_concurrent, input_size);
		idx_t batch_size = batch_end - batch_start;

		// Rate-limit: global first, then per-host, for each request in this batch
		for (idx_t i = batch_start; i < batch_end; i++) {
			AcquireRateLimit(GetGlobalLimiter(
			    rows[i].config.global_rate_limit_spec, rows[i].config.global_burst));
			AcquireRateLimit(GetRateLimiterRegistry().GetOrCreate(
			    rows[i].host, rows[i].config.rate_limit_spec, rows[i].config.burst));
		}

		// Build MultiPerform for this batch
		cpr::MultiPerform multi;
		for (idx_t i = batch_start; i < batch_end; i++) {
			multi.AddSession(rows[i].session, rows[i].cpr_method);
		}

		// Execute all requests in this batch concurrently
		std::vector<cpr::Response> responses;
		try {
			responses = multi.Perform();
		} catch (const std::exception &e) {
			duckdb_scalar_function_set_error(info, e.what());
			return;
		}

		// Collect results and record stats
		for (idx_t i = 0; i < batch_size; i++) {
			idx_t row_idx = batch_start + i;
			RecordResponseStats(responses[i], rows[row_idx].host);
			results[row_idx] = ResponseToResult(
			    responses[i], rows[row_idx].bind_data, rows[row_idx].req_headers);
		}
	}

	// --- Phase 3: Write results to struct output vector ---
	for (idx_t row = 0; row < input_size; row++) {
		WriteResultToStruct(output, row, results[row]);
	}
}

// Build the STRUCT return type matching the table function's output schema.
static duckdb_logical_type CreateHttpResultStructType() {
	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type int_type = duckdb_create_logical_type(DUCKDB_TYPE_INTEGER);
	duckdb_logical_type double_type = duckdb_create_logical_type(DUCKDB_TYPE_DOUBLE);

	duckdb_logical_type member_types[] = {
	    varchar_type, varchar_type, varchar_type, varchar_type,  // request_url, method, headers, body
	    int_type,                                                 // response_status_code
	    varchar_type, varchar_type, varchar_type, varchar_type,  // response_status, headers, body, url
	    double_type,                                              // elapsed
	    int_type                                                  // redirect_count
	};
	const char *member_names[] = {
	    "request_url", "request_method", "request_headers", "request_body",
	    "response_status_code",
	    "response_status", "response_headers", "response_body", "response_url",
	    "elapsed",
	    "redirect_count"
	};

	duckdb_logical_type struct_type = duckdb_create_struct_type(member_types, member_names, 11);

	duckdb_destroy_logical_type(&varchar_type);
	duckdb_destroy_logical_type(&int_type);
	duckdb_destroy_logical_type(&double_type);

	return struct_type;
}

//! Register a scalar HTTP function with the given name and volatility.
//! Both the idempotent and volatile variants share the same implementation;
//! they differ only in how the optimizer treats them.
static void RegisterHttpScalarVariant(duckdb_connection connection, const char *name, bool is_volatile) {
	duckdb_scalar_function function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(function, name);

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);

	// (method, url, headers_json, body, content_type, config_json)
	duckdb_scalar_function_add_parameter(function, varchar_type); // method
	duckdb_scalar_function_add_parameter(function, varchar_type); // url
	duckdb_scalar_function_add_parameter(function, varchar_type); // headers (JSON string)
	duckdb_scalar_function_add_parameter(function, varchar_type); // body
	duckdb_scalar_function_add_parameter(function, varchar_type); // content_type
	duckdb_scalar_function_add_parameter(function, varchar_type); // config (JSON string)

	duckdb_logical_type struct_type = CreateHttpResultStructType();
	duckdb_scalar_function_set_return_type(function, struct_type);
	duckdb_destroy_logical_type(&struct_type);
	duckdb_destroy_logical_type(&varchar_type);

	duckdb_scalar_function_set_function(function, HttpRawRequestScalarFunc);
	duckdb_scalar_function_set_special_handling(function);
	if (is_volatile) {
		duckdb_scalar_function_set_volatile(function);
	}

	duckdb_register_scalar_function(connection, function);
	duckdb_destroy_scalar_function(&function);
}

static void RegisterHttpRawRequestScalar(duckdb_connection connection) {
	// Idempotent variant: safe to deduplicate identical calls (GET, HEAD, etc.)
	RegisterHttpScalarVariant(connection, "_http_raw_request", false);
	// Volatile variant: every call fires regardless of argument identity (POST, PATCH, etc.)
	RegisterHttpScalarVariant(connection, "_http_raw_request_volatile", true);
}

// ---------------------------------------------------------------------------
// Table function: http_rate_limit_stats()
// Returns one row per host with rate limiter diagnostics.
// ---------------------------------------------------------------------------

struct RateLimitStatsData {
	struct HostStats {
		std::string host;
		std::string rate_spec;
		double rate_rps;
		double burst;
		uint64_t requests;
		uint64_t paced;
		double total_wait_seconds;
		uint64_t throttled_429;
		double backlog_seconds;
		// Response facts
		uint64_t total_responses;
		uint64_t total_response_bytes;
		double total_elapsed;
		double min_elapsed;
		double max_elapsed;
		uint64_t errors;
	};
	std::vector<HostStats> rows;
	idx_t current_row = 0;
};

static void DestroyRateLimitStatsData(void *data) {
	delete static_cast<RateLimitStatsData *>(data);
}

static void RateLimitStatsBind(duckdb_bind_info info) {
	// Snapshot the stats at bind time
	auto *data = new RateLimitStatsData();
	auto snapshot = [](const std::string &host, GCRARateLimiter &limiter) -> RateLimitStatsData::HostStats {
		return {host, limiter.RateSpec(), limiter.Rate(), limiter.Burst(), limiter.Requests(),
		    limiter.Paced(), limiter.TotalWaitSeconds(), limiter.Throttled429(), limiter.BacklogSeconds(),
		    limiter.TotalResponses(), limiter.TotalResponseBytes(), limiter.TotalElapsed(),
		    limiter.MinElapsed(), limiter.MaxElapsed(), limiter.Errors()};
	};

	// Include the global limiter as a special "(global)" row if configured
	auto *global = GetGlobalLimiterSnapshot();
	if (global) {
		data->rows.push_back(snapshot("(global)", *global));
	}

	GetRateLimiterRegistry().ForEach([&](const std::string &host, GCRARateLimiter &limiter) {
		data->rows.push_back(snapshot(host, limiter));
	});

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_logical_type bigint_type = duckdb_create_logical_type(DUCKDB_TYPE_BIGINT);
	duckdb_logical_type double_type = duckdb_create_logical_type(DUCKDB_TYPE_DOUBLE);

	duckdb_bind_add_result_column(info, "host", varchar_type);
	duckdb_bind_add_result_column(info, "rate_limit", varchar_type);
	duckdb_bind_add_result_column(info, "rate_rps", double_type);
	duckdb_bind_add_result_column(info, "burst", double_type);
	duckdb_bind_add_result_column(info, "requests", bigint_type);
	duckdb_bind_add_result_column(info, "paced", bigint_type);
	duckdb_bind_add_result_column(info, "total_wait_seconds", double_type);
	duckdb_bind_add_result_column(info, "throttled_429", bigint_type);
	duckdb_bind_add_result_column(info, "backlog_seconds", double_type);
	duckdb_bind_add_result_column(info, "total_responses", bigint_type);
	duckdb_bind_add_result_column(info, "total_response_bytes", bigint_type);
	duckdb_bind_add_result_column(info, "total_elapsed", double_type);
	duckdb_bind_add_result_column(info, "min_elapsed", double_type);
	duckdb_bind_add_result_column(info, "max_elapsed", double_type);
	duckdb_bind_add_result_column(info, "errors", bigint_type);

	duckdb_destroy_logical_type(&varchar_type);
	duckdb_destroy_logical_type(&bigint_type);
	duckdb_destroy_logical_type(&double_type);

	duckdb_bind_set_cardinality(info, data->rows.size(), true);
	duckdb_bind_set_bind_data(info, data, DestroyRateLimitStatsData);
}

static void RateLimitStatsInit(duckdb_init_info info) {
	// No per-thread state needed; we use bind_data.current_row
}

static void RateLimitStatsExecute(duckdb_function_info info, duckdb_data_chunk output) {
	auto *data = static_cast<RateLimitStatsData *>(duckdb_function_get_bind_data(info));

	idx_t remaining = data->rows.size() - data->current_row;
	idx_t count = std::min(remaining, duckdb_vector_size());
	if (count == 0) {
		duckdb_data_chunk_set_size(output, 0);
		return;
	}

	duckdb_vector host_vec = duckdb_data_chunk_get_vector(output, 0);
	duckdb_vector rate_limit_vec = duckdb_data_chunk_get_vector(output, 1);
	duckdb_vector rate_rps_vec = duckdb_data_chunk_get_vector(output, 2);
	duckdb_vector burst_vec = duckdb_data_chunk_get_vector(output, 3);
	duckdb_vector requests_vec = duckdb_data_chunk_get_vector(output, 4);
	duckdb_vector paced_vec = duckdb_data_chunk_get_vector(output, 5);
	duckdb_vector wait_vec = duckdb_data_chunk_get_vector(output, 6);
	duckdb_vector throttled_vec = duckdb_data_chunk_get_vector(output, 7);
	duckdb_vector backlog_vec = duckdb_data_chunk_get_vector(output, 8);
	duckdb_vector total_resp_vec = duckdb_data_chunk_get_vector(output, 9);
	duckdb_vector total_bytes_vec = duckdb_data_chunk_get_vector(output, 10);
	duckdb_vector total_elapsed_vec = duckdb_data_chunk_get_vector(output, 11);
	duckdb_vector min_elapsed_vec = duckdb_data_chunk_get_vector(output, 12);
	duckdb_vector max_elapsed_vec = duckdb_data_chunk_get_vector(output, 13);
	duckdb_vector errors_vec = duckdb_data_chunk_get_vector(output, 14);

	auto *rate_rps_data = (double *)duckdb_vector_get_data(rate_rps_vec);
	auto *burst_data = (double *)duckdb_vector_get_data(burst_vec);
	auto *requests_data = (int64_t *)duckdb_vector_get_data(requests_vec);
	auto *paced_data = (int64_t *)duckdb_vector_get_data(paced_vec);
	auto *wait_data = (double *)duckdb_vector_get_data(wait_vec);
	auto *throttled_data = (int64_t *)duckdb_vector_get_data(throttled_vec);
	auto *backlog_data = (double *)duckdb_vector_get_data(backlog_vec);
	auto *total_resp_data = (int64_t *)duckdb_vector_get_data(total_resp_vec);
	auto *total_bytes_data = (int64_t *)duckdb_vector_get_data(total_bytes_vec);
	auto *total_elapsed_data = (double *)duckdb_vector_get_data(total_elapsed_vec);
	auto *min_elapsed_data = (double *)duckdb_vector_get_data(min_elapsed_vec);
	auto *max_elapsed_data = (double *)duckdb_vector_get_data(max_elapsed_vec);
	auto *errors_data = (int64_t *)duckdb_vector_get_data(errors_vec);

	for (idx_t i = 0; i < count; i++) {
		auto &row = data->rows[data->current_row + i];
		duckdb_vector_assign_string_element_len(host_vec, i, row.host.c_str(), row.host.length());
		duckdb_vector_assign_string_element_len(rate_limit_vec, i, row.rate_spec.c_str(), row.rate_spec.length());
		rate_rps_data[i] = row.rate_rps;
		burst_data[i] = row.burst;
		requests_data[i] = static_cast<int64_t>(row.requests);
		paced_data[i] = static_cast<int64_t>(row.paced);
		wait_data[i] = row.total_wait_seconds;
		throttled_data[i] = static_cast<int64_t>(row.throttled_429);
		backlog_data[i] = row.backlog_seconds;
		total_resp_data[i] = static_cast<int64_t>(row.total_responses);
		total_bytes_data[i] = static_cast<int64_t>(row.total_response_bytes);
		total_elapsed_data[i] = row.total_elapsed;
		min_elapsed_data[i] = row.min_elapsed;
		max_elapsed_data[i] = row.max_elapsed;
		errors_data[i] = static_cast<int64_t>(row.errors);
	}

	data->current_row += count;
	duckdb_data_chunk_set_size(output, count);
}

static void RegisterRateLimitStatsFunction(duckdb_connection connection) {
	duckdb_table_function function = duckdb_create_table_function();
	duckdb_table_function_set_name(function, "http_rate_limit_stats");

	duckdb_table_function_set_bind(function, RateLimitStatsBind);
	duckdb_table_function_set_init(function, RateLimitStatsInit);
	duckdb_table_function_set_function(function, RateLimitStatsExecute);

	duckdb_register_table_function(connection, function);
	duckdb_destroy_table_function(&function);
}

// ---------------------------------------------------------------------------
// SQL macro registration: user-facing wrappers that inject config
// ---------------------------------------------------------------------------

//! Helper: try to register a SQL macro via duckdb_query. Ignores errors on
//! individual macros so the extension still loads if a macro fails.
static void TryRegisterMacro(duckdb_connection connection, const char *sql) {
	duckdb_result result;
	duckdb_query(connection, sql, &result);
	duckdb_destroy_result(&result);
}

void RegisterHttpMacros(duckdb_connection connection) {
	// Helper macro to safely read the http_config variable.
	// Returns an empty MAP if the variable is not set.
	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO _http_config() AS "
		"IFNULL(TRY_CAST(getvariable('http_config') AS MAP(VARCHAR, VARCHAR)), MAP {})");

	// Table function macros: http_get, http_post, etc.
	// These read http_config from the caller's connection and pass it to _http_raw.
	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_get(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('GET', url, headers := headers, params := params, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_post(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR, timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('POST', url, headers := headers, params := params, "
		"body := body, content_type := content_type, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_put(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR, timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('PUT', url, headers := headers, params := params, "
		"body := body, content_type := content_type, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_delete(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('DELETE', url, headers := headers, params := params, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_patch(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR, timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('PATCH', url, headers := headers, params := params, "
		"body := body, content_type := content_type, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_head(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('HEAD', url, headers := headers, params := params, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_options(url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw('OPTIONS', url, headers := headers, params := params, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_do(method, url, headers := NULL::MAP(VARCHAR, VARCHAR), "
		"params := NULL::MAP(VARCHAR, VARCHAR), body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR, timeout := NULL::INTEGER, "
		"verify_ssl := NULL::BOOLEAN) AS TABLE "
		"SELECT * FROM _http_raw(method, url, headers := headers, params := params, "
		"body := body, content_type := content_type, "
		"timeout := timeout, verify_ssl := verify_ssl, _config := _http_config())");

	// --- Scalar macros ---
	// Per-verb scalar macros route to the idempotent or volatile variant
	// based on HTTP method semantics.

	// Idempotent verbs: safe to deduplicate identical calls within a query.
	// GET, HEAD, OPTIONS are read-only; PUT and DELETE are idempotent by spec.
	const char *idempotent_scalar_macros[] = {
		"CREATE OR REPLACE MACRO http_get_s(url, "
		"headers := NULL::VARCHAR) AS "
		"_http_raw_request('GET', url, headers, NULL, NULL, "
		"CAST(_http_config() AS JSON))",

		"CREATE OR REPLACE MACRO http_head_s(url, "
		"headers := NULL::VARCHAR) AS "
		"_http_raw_request('HEAD', url, headers, NULL, NULL, "
		"CAST(_http_config() AS JSON))",

		"CREATE OR REPLACE MACRO http_options_s(url, "
		"headers := NULL::VARCHAR) AS "
		"_http_raw_request('OPTIONS', url, headers, NULL, NULL, "
		"CAST(_http_config() AS JSON))",

		"CREATE OR REPLACE MACRO http_put_s(url, "
		"headers := NULL::VARCHAR, body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR) AS "
		"_http_raw_request('PUT', url, headers, body, content_type, "
		"CAST(_http_config() AS JSON))",

		"CREATE OR REPLACE MACRO http_delete_s(url, "
		"headers := NULL::VARCHAR) AS "
		"_http_raw_request('DELETE', url, headers, NULL, NULL, "
		"CAST(_http_config() AS JSON))",
	};
	for (auto *sql : idempotent_scalar_macros) {
		TryRegisterMacro(connection, sql);
	}

	// Non-idempotent verbs: volatile, every call fires.
	const char *volatile_scalar_macros[] = {
		"CREATE OR REPLACE MACRO http_post_s(url, "
		"headers := NULL::VARCHAR, body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR) AS "
		"_http_raw_request_volatile('POST', url, headers, body, content_type, "
		"CAST(_http_config() AS JSON))",

		"CREATE OR REPLACE MACRO http_patch_s(url, "
		"headers := NULL::VARCHAR, body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR) AS "
		"_http_raw_request_volatile('PATCH', url, headers, body, content_type, "
		"CAST(_http_config() AS JSON))",
	};
	for (auto *sql : volatile_scalar_macros) {
		TryRegisterMacro(connection, sql);
	}

	// Generic scalar: method is a runtime parameter, so must be volatile
	// (we can't know at compile time whether it's idempotent).
	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_request(method, url, "
		"headers := NULL::VARCHAR, body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR) AS "
		"_http_raw_request_volatile(method, url, headers, body, content_type, "
		"CAST(_http_config() AS JSON))");

	// JSON variants: wrap the STRUCT with to_json().
	TryRegisterMacro(connection,
		"CREATE OR REPLACE MACRO http_request_json(method, url, "
		"headers := NULL::VARCHAR, body := NULL::VARCHAR, "
		"content_type := NULL::VARCHAR) AS "
		"to_json(_http_raw_request_volatile(method, url, headers, body, content_type, "
		"CAST(_http_config() AS JSON)))");
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

void RegisterHttpFunctions(duckdb_connection connection) {
	// Raw C functions (prefixed with _ — not intended for direct use)
	RegisterHttpRawTableFunction(connection);
	RegisterHttpRawRequestScalar(connection);

	// Diagnostics
	RegisterRateLimitStatsFunction(connection);

	// SQL macros: user-facing wrappers that inject config
	RegisterHttpMacros(connection);
}

} // namespace http_client
