#pragma once

#include "duckdb_extension.h"

void RegisterNegotiateAuthFunction(duckdb_connection connection);

namespace http_client {
void RegisterHttpFunctions(duckdb_connection connection);
} // namespace http_client
