#pragma once

#include <nlohmann/json.hpp>
#include <string>

namespace http_client {

//! Resolved configuration for a single HTTP request.
//! Built by merging: per-call overrides > scope match > default > hard-coded fallbacks.
struct HttpConfig {
	double rate_limit_rps = 20.0;  // requests per second (parsed from rate_limit string)
	std::string rate_limit_spec = "20/s";
	double burst = 5.0;
	int timeout = 30;              // seconds
	bool verify_ssl = true;
	std::string proxy;             // empty = no proxy
	std::string ca_bundle;         // empty = system default
	std::string auth_type;         // "negotiate", "bearer", or empty
	std::string bearer_token;      // for auth_type=bearer

	//! Apply values from a JSON config object, overwriting only fields that are present.
	void MergeFrom(const nlohmann::json &j) {
		if (j.contains("rate_limit") && j["rate_limit"].is_string()) {
			rate_limit_spec = j["rate_limit"].get<std::string>();
		}
		if (j.contains("burst") && j["burst"].is_number()) {
			burst = j["burst"].get<double>();
		}
		if (j.contains("timeout") && j["timeout"].is_number()) {
			timeout = j["timeout"].get<int>();
		}
		if (j.contains("verify_ssl") && j["verify_ssl"].is_boolean()) {
			verify_ssl = j["verify_ssl"].get<bool>();
		}
		if (j.contains("proxy") && j["proxy"].is_string()) {
			proxy = j["proxy"].get<std::string>();
		}
		if (j.contains("ca_bundle") && j["ca_bundle"].is_string()) {
			ca_bundle = j["ca_bundle"].get<std::string>();
		}
		if (j.contains("auth_type") && j["auth_type"].is_string()) {
			auth_type = j["auth_type"].get<std::string>();
		}
		if (j.contains("bearer_token") && j["bearer_token"].is_string()) {
			bearer_token = j["bearer_token"].get<std::string>();
		}
	}
};

//! Resolve the HttpConfig for a given URL by reading the http_config variable.
//! The config_map_json is the result of querying getvariable('http_config') cast to JSON,
//! represented as a map of scope -> json-config-string.
//!
//! Resolution order:
//! 1. Hard-coded defaults (in HttpConfig struct)
//! 2. "default" key from the config map
//! 3. Longest matching scope prefix
//! 4. Per-call overrides (applied by the caller after this function returns)
inline HttpConfig ResolveConfig(const std::string &url,
                                const std::vector<std::pair<std::string, std::string>> &config_entries) {
	HttpConfig config;

	// Apply "default" entry first
	for (auto &[scope, json_str] : config_entries) {
		if (scope == "default") {
			try {
				config.MergeFrom(nlohmann::json::parse(json_str));
			} catch (...) {
				// Malformed JSON in default config — skip it
			}
			break;
		}
	}

	// Find longest matching scope prefix
	std::string best_scope;
	std::string best_json;
	for (auto &[scope, json_str] : config_entries) {
		if (scope == "default") {
			continue;
		}
		if (url.rfind(scope, 0) == 0 && scope.length() > best_scope.length()) {
			best_scope = scope;
			best_json = json_str;
		}
	}

	// Apply the best scope match on top of defaults
	if (!best_scope.empty()) {
		try {
			config.MergeFrom(nlohmann::json::parse(best_json));
		} catch (...) {
			// Malformed JSON in scope config — skip it
		}
	}

	return config;
}

} // namespace http_client
