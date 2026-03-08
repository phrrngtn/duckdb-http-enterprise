#include "duckdb_extension.h"
#include "http_client_extension.hpp"
#include "negotiate_auth.hpp"

#include <cstring>
#include <string>

DUCKDB_EXTENSION_EXTERN

// ---------------------------------------------------------------------------
// negotiate_auth_header(url) -> VARCHAR
// Returns 'Negotiate <base64-token>' for the given HTTPS URL, or throws.
// ---------------------------------------------------------------------------

static void NegotiateAuthHeaderFunc(duckdb_function_info info, duckdb_data_chunk input, duckdb_vector output) {
	idx_t input_size = duckdb_data_chunk_get_size(input);
	duckdb_vector url_vec = duckdb_data_chunk_get_vector(input, 0);

	auto url_data = (duckdb_string_t *)duckdb_vector_get_data(url_vec);

	for (idx_t row = 0; row < input_size; row++) {
		auto url_str = duckdb_string_t_data(&url_data[row]);
		auto url_len = duckdb_string_t_length(url_data[row]);

		std::string url(url_str, url_len);
		std::string error_msg;
		std::string token;

		try {
			token = http_client::GenerateNegotiateToken(url);
		} catch (const std::exception &e) {
			error_msg = e.what();
		}

		if (!error_msg.empty()) {
			duckdb_scalar_function_set_error(info, error_msg.c_str());
			return;
		}

		std::string header = "Negotiate " + token;
		duckdb_vector_assign_string_element_len(output, row, header.c_str(), header.length());
	}
}

void RegisterNegotiateAuthFunction(duckdb_connection connection) {
	duckdb_scalar_function function = duckdb_create_scalar_function();
	duckdb_scalar_function_set_name(function, "negotiate_auth_header");

	duckdb_logical_type varchar_type = duckdb_create_logical_type(DUCKDB_TYPE_VARCHAR);
	duckdb_scalar_function_add_parameter(function, varchar_type);
	duckdb_scalar_function_set_return_type(function, varchar_type);
	duckdb_destroy_logical_type(&varchar_type);

	duckdb_scalar_function_set_function(function, NegotiateAuthHeaderFunc);

	duckdb_register_scalar_function(connection, function);
	duckdb_destroy_scalar_function(&function);
}

// ---------------------------------------------------------------------------
// Extension entry point
// ---------------------------------------------------------------------------

DUCKDB_EXTENSION_ENTRYPOINT(duckdb_connection connection, duckdb_extension_info info,
                            struct duckdb_extension_access *access) {
	RegisterNegotiateAuthFunction(connection);
	return true;
}
