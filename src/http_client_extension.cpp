#include "duckdb_extension.h"
#include "http_client_extension.hpp"
#include "negotiate_auth.hpp"

#include <cstring>
#include <string>

#include <nlohmann/json.hpp>

DUCKDB_EXTENSION_EXTERN

// ---------------------------------------------------------------------------
// negotiate_auth_token(url) -> VARCHAR
// Returns the base64-encoded SPNEGO token for the given HTTPS URL.
// ---------------------------------------------------------------------------

static void NegotiateAuthTokenFunc(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t input_size = duckdb_data_chunk_get_size(input);
	duckdb_vector url_vec = duckdb_data_chunk_get_vector(input, 0);

	auto url_data = (duckdb_string_t *)duckdb_vector_get_data(url_vec);

	for (idx_t row = 0; row < input_size; row++) {
		auto url_str = duckdb_string_t_data(&url_data[row]);
		auto url_len = duckdb_string_t_length(url_data[row]);

		std::string url(url_str, url_len);
		std::string error_msg;

		try {
			auto result = http_client::GenerateNegotiateToken(url);
			std::string header = "Negotiate " + result.token;
			duckdb_vector_assign_string_element_len(output, row, header.c_str(), header.length());
		} catch (const std::exception &e) {
			duckdb_scalar_function_set_error(info, e.what());
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// negotiate_auth_token_json(url) -> VARCHAR (JSON)
// Returns a JSON object with the token and debugging metadata.
// ---------------------------------------------------------------------------

static void NegotiateAuthTokenJsonFunc(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t input_size = duckdb_data_chunk_get_size(input);
	duckdb_vector url_vec = duckdb_data_chunk_get_vector(input, 0);

	auto url_data = (duckdb_string_t *)duckdb_vector_get_data(url_vec);

	for (idx_t row = 0; row < input_size; row++) {
		auto url_str = duckdb_string_t_data(&url_data[row]);
		auto url_len = duckdb_string_t_length(url_data[row]);

		std::string url(url_str, url_len);

		try {
			auto result = http_client::GenerateNegotiateToken(url);

			nlohmann::json j;
			j["token"] = result.token;
			j["header"] = "Negotiate " + result.token;
			j["url"] = result.url;
			j["hostname"] = result.hostname;
			j["spn"] = result.spn;
			j["provider"] = result.provider;
			j["library"] = result.library;

			auto json_str = j.dump();
			duckdb_vector_assign_string_element_len(output, row, json_str.c_str(), json_str.length());
		} catch (const std::exception &e) {
			duckdb_scalar_function_set_error(info, e.what());
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// Function registration helpers
// ---------------------------------------------------------------------------

static void RegisterScalarVarcharFunction(duckdb_connection connection, const char *name,
                                          duckdb_scalar_function_t func) {
	duckdb_scalar_function function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(function, name);

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_scalar_function_add_parameter(function, varchar_type);
	duckdb_scalar_function_set_return_type(function, varchar_type);
	duckdb_destroy_logical_type(&varchar_type);

	duckdb_scalar_function_set_function(function, func);

	duckdb_register_scalar_function(connection, function);
	duckdb_destroy_scalar_function(&function);
}

// ---------------------------------------------------------------------------
// Extension entry point
// ---------------------------------------------------------------------------

DUCKDB_EXTENSION_ENTRYPOINT(duckdb_connection connection, duckdb_extension_info info,
                            struct duckdb_extension_access *access) {
	RegisterScalarVarcharFunction(connection, "negotiate_auth_header", NegotiateAuthTokenFunc);
	RegisterScalarVarcharFunction(connection, "negotiate_auth_header_json", NegotiateAuthTokenJsonFunc);
	http_client::RegisterHttpFunctions(connection);
	return true;
}
