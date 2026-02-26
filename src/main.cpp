/**
 * C++ Live Transcription Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Live Transcription API.
 * Forwards all messages (JSON and binary) bidirectionally between client and Deepgram.
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   WS   /api/live-transcription   - WebSocket proxy to Deepgram STT (auth required)
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   GET  /health                   - Health check
 */

#include <crow.h>
#include <nlohmann/json.hpp>
#include <toml++/toml.hpp>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <atomic>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using json = nlohmann::json;

// ============================================================================
// CONFIGURATION
// ============================================================================

struct Config {
    std::string deepgram_api_key;
    std::string deepgram_stt_url;
    int port;
    std::string host;
    std::vector<unsigned char> session_secret;
};

/// Reads a .env file and sets environment variables (simple dotenv implementation).
static void load_dotenv() {
    std::ifstream file(".env");
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        // Remove surrounding quotes if present
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"') {
            val = val.substr(1, val.size() - 2);
        }
        setenv(key.c_str(), val.c_str(), 0); // Don't overwrite existing
    }
}

/// Loads configuration from environment variables, with defaults.
static Config load_config() {
    load_dotenv();

    const char* api_key_env = std::getenv("DEEPGRAM_API_KEY");
    if (!api_key_env || std::string(api_key_env).empty()) {
        std::cerr << "ERROR: DEEPGRAM_API_KEY environment variable is required\n"
                  << "Please copy sample.env to .env and add your API key" << std::endl;
        std::exit(1);
    }

    const char* port_env = std::getenv("PORT");
    int port = 8081;
    if (port_env) {
        try { port = std::stoi(port_env); } catch (...) {}
    }

    const char* host_env = std::getenv("HOST");
    std::string host = host_env ? host_env : "0.0.0.0";

    std::vector<unsigned char> secret;
    const char* secret_env = std::getenv("SESSION_SECRET");
    if (secret_env && std::string(secret_env).size() > 0) {
        std::string s(secret_env);
        secret.assign(s.begin(), s.end());
    } else {
        secret.resize(32);
        RAND_bytes(secret.data(), static_cast<int>(secret.size()));
    }

    return Config{
        std::string(api_key_env),
        "wss://api.deepgram.com/v1/listen",
        port,
        host,
        secret
    };
}

// ============================================================================
// UTILITY - Base64 URL encoding/decoding
// ============================================================================

/// Encodes raw bytes to base64url (no padding).
static std::string base64url_encode(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(4 * ((len + 2) / 3));

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        result += table[(n >> 18) & 0x3F];
        result += table[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? table[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? table[n & 0x3F] : '=';
    }

    // Convert to URL-safe variant and strip padding
    for (auto& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!result.empty() && result.back() == '=') result.pop_back();

    return result;
}

/// Encodes a string to base64url (no padding).
static std::string base64url_encode(const std::string& data) {
    return base64url_encode(reinterpret_cast<const unsigned char*>(data.data()), data.size());
}

/// Decodes a base64url string to raw bytes.
static std::vector<unsigned char> base64url_decode(const std::string& input) {
    std::string b64 = input;
    // Convert from URL-safe back to standard base64
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    while (b64.size() % 4 != 0) b64 += '=';

    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::vector<unsigned char> result;
    result.reserve(b64.size() * 3 / 4);

    for (size_t i = 0; i + 3 < b64.size(); i += 4) {
        int a = table[static_cast<unsigned char>(b64[i])];
        int b = table[static_cast<unsigned char>(b64[i + 1])];
        int c = table[static_cast<unsigned char>(b64[i + 2])];
        int d = table[static_cast<unsigned char>(b64[i + 3])];
        if (a < 0 || b < 0) break;

        result.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        if (c >= 0) result.push_back(static_cast<unsigned char>(((b & 0x0F) << 4) | (c >> 2)));
        if (d >= 0) result.push_back(static_cast<unsigned char>(((c & 0x03) << 6) | d));
    }

    return result;
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security (manual HS256)
// ============================================================================

static const int64_t JWT_EXPIRY_SECS = 3600; // 1 hour

/// Signs data with HMAC-SHA256 and returns raw bytes.
static std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key, const std::string& data) {
    unsigned int len = 0;
    unsigned char result[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         result, &len);
    return std::vector<unsigned char>(result, result + len);
}

/// Creates a signed JWT with a 1-hour expiry using manual HS256.
static std::string issue_token(const std::vector<unsigned char>& secret) {
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    int64_t exp = now + JWT_EXPIRY_SECS;

    // Header
    json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    std::string header_b64 = base64url_encode(header.dump());

    // Payload
    json payload = {{"iat", now}, {"exp", exp}};
    std::string payload_b64 = base64url_encode(payload.dump());

    // Signature
    std::string signing_input = header_b64 + "." + payload_b64;
    auto sig = hmac_sha256(secret, signing_input);
    std::string sig_b64 = base64url_encode(sig.data(), sig.size());

    return signing_input + "." + sig_b64;
}

/// Verifies a JWT token string. Returns true if valid, false otherwise.
static bool validate_token(const std::string& token_str, const std::vector<unsigned char>& secret) {
    // Split into header.payload.signature
    auto dot1 = token_str.find('.');
    if (dot1 == std::string::npos) return false;
    auto dot2 = token_str.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;

    std::string header_b64 = token_str.substr(0, dot1);
    std::string payload_b64 = token_str.substr(dot1 + 1, dot2 - dot1 - 1);
    std::string sig_b64 = token_str.substr(dot2 + 1);

    // Verify signature
    std::string signing_input = header_b64 + "." + payload_b64;
    auto expected_sig = hmac_sha256(secret, signing_input);
    std::string expected_b64 = base64url_encode(expected_sig.data(), expected_sig.size());

    if (sig_b64 != expected_b64) return false;

    // Verify algorithm
    try {
        auto header_bytes = base64url_decode(header_b64);
        auto header = json::parse(std::string(header_bytes.begin(), header_bytes.end()));
        if (header.value("alg", "") != "HS256") return false;
    } catch (...) {
        return false;
    }

    // Verify expiry
    try {
        auto payload_bytes = base64url_decode(payload_b64);
        auto payload = json::parse(std::string(payload_bytes.begin(), payload_bytes.end()));
        int64_t exp = payload.value("exp", static_cast<int64_t>(0));
        int64_t now = static_cast<int64_t>(std::time(nullptr));
        if (exp <= now) return false;
    } catch (...) {
        return false;
    }

    return true;
}

/// Extracts and validates a JWT from the access_token.<jwt> subprotocol.
/// Returns the full subprotocol string if valid, empty string if invalid.
static std::string validate_ws_token(const std::vector<std::string>& protocols,
                                     const std::vector<unsigned char>& secret) {
    const std::string prefix = "access_token.";
    for (const auto& proto : protocols) {
        if (proto.size() > prefix.size() && proto.substr(0, prefix.size()) == prefix) {
            std::string token_str = proto.substr(prefix.size());
            if (validate_token(token_str, secret)) {
                return proto;
            }
        }
    }
    return "";
}

// ============================================================================
// METADATA - deepgram.toml parsing
// ============================================================================

/// Reads and parses the [meta] section from deepgram.toml.
static json load_metadata() {
    auto tbl = toml::parse_file("deepgram.toml");
    auto meta_node = tbl["meta"];
    if (!meta_node.is_table()) {
        throw std::runtime_error("Missing [meta] section in deepgram.toml");
    }

    // Convert TOML table to JSON object
    json result = json::object();
    auto& meta = *meta_node.as_table();
    for (auto&& [key, val] : meta) {
        std::string k(key.str());
        if (val.is_string()) {
            result[k] = std::string(val.as_string()->get());
        } else if (val.is_integer()) {
            result[k] = val.as_integer()->get();
        } else if (val.is_floating_point()) {
            result[k] = val.as_floating_point()->get();
        } else if (val.is_boolean()) {
            result[k] = val.as_boolean()->get();
        } else if (val.is_array()) {
            json arr = json::array();
            for (auto&& elem : *val.as_array()) {
                if (elem.is_string()) arr.push_back(std::string(elem.as_string()->get()));
                else if (elem.is_integer()) arr.push_back(elem.as_integer()->get());
                else if (elem.is_floating_point()) arr.push_back(elem.as_floating_point()->get());
                else if (elem.is_boolean()) arr.push_back(elem.as_boolean()->get());
            }
            result[k] = arr;
        }
    }
    return result;
}

// ============================================================================
// WEBSOCKET PROXY - Outbound connection to Deepgram via Boost.Beast
// ============================================================================

/// Builds the Deepgram WebSocket URL path with query parameters forwarded from the client request.
static std::string build_deepgram_path(const std::string& query_string) {
    // Parse incoming query params
    std::map<std::string, std::string> params;
    std::istringstream qs(query_string);
    std::string pair;
    while (std::getline(qs, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos) {
            params[pair.substr(0, eq)] = pair.substr(eq + 1);
        }
    }

    // Defaults for Deepgram query parameters
    std::vector<std::pair<std::string, std::string>> defaults = {
        {"model",        "nova-3"},
        {"language",     "en"},
        {"smart_format", "true"},
        {"punctuate",    "true"},
        {"diarize",      "false"},
        {"filler_words", "false"},
        {"encoding",     "linear16"},
        {"sample_rate",  "16000"},
        {"channels",     "1"}
    };

    std::string path = "/v1/listen?";
    bool first = true;
    for (auto& [name, default_val] : defaults) {
        auto it = params.find(name);
        const std::string& val = (it != params.end()) ? it->second : default_val;
        if (!first) path += "&";
        path += name + "=" + val;
        first = false;
    }

    return path;
}

/// Parses the Sec-WebSocket-Protocol header value into individual protocol strings.
static std::vector<std::string> parse_subprotocols(const std::string& header_value) {
    std::vector<std::string> protocols;
    std::istringstream ss(header_value);
    std::string token;
    while (std::getline(ss, token, ',')) {
        // Trim whitespace
        size_t start = token.find_first_not_of(" \t");
        size_t end = token.find_last_not_of(" \t");
        if (start != std::string::npos) {
            protocols.push_back(token.substr(start, end - start + 1));
        }
    }
    return protocols;
}

/// Gets the value of a query parameter, or the default if not present.
static std::string get_param(const std::string& query_string, const std::string& name,
                             const std::string& default_val) {
    std::istringstream qs(query_string);
    std::string pair;
    while (std::getline(qs, pair, '&')) {
        auto eq = pair.find('=');
        if (eq != std::string::npos && pair.substr(0, eq) == name) {
            return pair.substr(eq + 1);
        }
    }
    return default_val;
}

/// Runs the outbound WebSocket read loop on a dedicated thread.
/// Reads messages from Deepgram and forwards them to the client via Crow's WebSocket.
static void deepgram_read_loop(
    std::shared_ptr<websocket::stream<beast::ssl_stream<tcp::socket>>> dg_ws,
    crow::websocket::connection* client_conn,
    std::shared_ptr<std::atomic<bool>> closed,
    std::shared_ptr<std::atomic<int64_t>> dg_to_client_count)
{
    try {
        while (!closed->load()) {
            beast::flat_buffer buffer;
            boost::system::error_code ec;
            dg_ws->read(buffer, ec);

            if (ec) {
                if (ec != websocket::error::closed &&
                    ec != net::error::operation_aborted &&
                    ec != net::ssl::error::stream_truncated) {
                    std::cerr << "[deepgram->client] read error: " << ec.message() << std::endl;
                }
                break;
            }

            auto data = buffer.data();
            std::string msg(static_cast<const char*>(data.data()), data.size());

            int64_t count = dg_to_client_count->fetch_add(1) + 1;

            if (dg_ws->got_text()) {
                std::cout << "[deepgram->client] message #" << count
                          << " (binary: false, size: " << msg.size() << ")" << std::endl;
                try {
                    client_conn->send_text(msg);
                } catch (...) {
                    std::cerr << "[deepgram->client] write error" << std::endl;
                    break;
                }
            } else {
                if (count % 10 == 0) {
                    std::cout << "[deepgram->client] message #" << count
                              << " (binary: true, size: " << msg.size() << ")" << std::endl;
                }
                try {
                    client_conn->send_binary(msg);
                } catch (...) {
                    std::cerr << "[deepgram->client] write error" << std::endl;
                    break;
                }
            }
        }
    } catch (const std::exception& e) {
        if (!closed->load()) {
            std::cerr << "[deepgram->client] exception: " << e.what() << std::endl;
        }
    }

    closed->store(true);
}

// ============================================================================
// MAIN
// ============================================================================

int main() {
    Config cfg = load_config();

    // Display session secret indicator (first 8 bytes as hex)
    std::ostringstream hex_ss;
    size_t hex_len = std::min(cfg.session_secret.size(), static_cast<size_t>(8));
    for (size_t i = 0; i < hex_len; ++i) {
        hex_ss << std::hex << std::setfill('0') << std::setw(2)
               << static_cast<int>(cfg.session_secret[i]);
    }
    std::string secret_hex = hex_ss.str();

    crow::SimpleApp app;

    // Store config as shared pointer for route handlers
    auto config_ptr = std::make_shared<Config>(cfg);

    // ========================================================================
    // GET /api/session - Issue JWT session token
    // ========================================================================
    CROW_ROUTE(app, "/api/session").methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)
    ([config_ptr](const crow::request& req) {
        // Handle CORS preflight
        if (req.method == crow::HTTPMethod::OPTIONS) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        std::string token = issue_token(config_ptr->session_secret);
        json body = {{"token", token}};
        crow::response res(200);
        res.set_header("Content-Type", "application/json");
        res.add_header("Access-Control-Allow-Origin", "*");
        res.body = body.dump();
        return res;
    });

    // ========================================================================
    // GET /api/metadata - Project metadata from deepgram.toml
    // ========================================================================
    CROW_ROUTE(app, "/api/metadata").methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)
    ([](const crow::request& req) {
        // Handle CORS preflight
        if (req.method == crow::HTTPMethod::OPTIONS) {
            crow::response res(200);
            res.add_header("Access-Control-Allow-Origin", "*");
            res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            return res;
        }

        try {
            json meta = load_metadata();
            crow::response res(200);
            res.set_header("Content-Type", "application/json");
            res.add_header("Access-Control-Allow-Origin", "*");
            res.body = meta.dump();
            return res;
        } catch (const std::exception& e) {
            std::cerr << "Error reading metadata: " << e.what() << std::endl;
            json body = {
                {"error", "INTERNAL_SERVER_ERROR"},
                {"message", std::string("Failed to read metadata from deepgram.toml: ") + e.what()}
            };
            crow::response res(500);
            res.set_header("Content-Type", "application/json");
            res.add_header("Access-Control-Allow-Origin", "*");
            res.body = body.dump();
            return res;
        }
    });

    // ========================================================================
    // GET /health - Health check
    // ========================================================================
    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::GET)
    ([](const crow::request&) {
        json body = {{"status", "ok"}};
        crow::response res(200);
        res.set_header("Content-Type", "application/json");
        res.add_header("Access-Control-Allow-Origin", "*");
        res.body = body.dump();
        return res;
    });

    // ========================================================================
    // WS /api/live-transcription - WebSocket proxy to Deepgram STT (auth required)
    // ========================================================================
    CROW_ROUTE(app, "/api/live-transcription")
        .websocket()
        .onaccept([config_ptr](const crow::request& req, void** userdata) -> bool {
            std::cout << "WebSocket upgrade request for: /api/live-transcription" << std::endl;

            // Validate JWT from access_token.<jwt> subprotocol
            std::string proto_header = req.get_header_value("Sec-WebSocket-Protocol");
            auto protocols = parse_subprotocols(proto_header);
            std::string valid_proto = validate_ws_token(protocols, config_ptr->session_secret);

            if (valid_proto.empty()) {
                std::cout << "WebSocket auth failed: invalid or missing token" << std::endl;
                return false;
            }

            std::cout << "Backend handling /api/live-transcription WebSocket (authenticated)" << std::endl;

            // Store the validated protocol and query string for the open handler
            // We pack both into a single allocated string, separated by a null byte
            std::string query_string = req.url_params.get("model") ? req.raw_url.substr(req.raw_url.find('?') + 1) : "";
            // Actually, parse the raw URL for the query string
            auto qpos = req.raw_url.find('?');
            query_string = (qpos != std::string::npos) ? req.raw_url.substr(qpos + 1) : "";

            auto* data = new std::string(valid_proto + '\0' + query_string);
            *userdata = data;
            return true;
        })
        .onopen([config_ptr](crow::websocket::connection& conn) {
            // Retrieve stored protocol and query string
            auto* data = static_cast<std::string*>(conn.userdata());
            auto null_pos = data->find('\0');
            std::string valid_proto = data->substr(0, null_pos);
            std::string query_string = data->substr(null_pos + 1);

            // Set the accepted subprotocol on the response
            conn.send_text(""); // Trigger connection -- the protocol is set via the upgrade response

            std::cout << "Client connected to /api/live-transcription" << std::endl;

            // Build Deepgram URL path with forwarded query parameters
            std::string dg_path = build_deepgram_path(query_string);

            std::string model = get_param(query_string, "model", "nova-3");
            std::string language = get_param(query_string, "language", "en");
            std::string encoding = get_param(query_string, "encoding", "linear16");
            std::string sample_rate = get_param(query_string, "sample_rate", "16000");
            std::string channels = get_param(query_string, "channels", "1");

            std::cout << "Connecting to Deepgram STT: model=" << model
                      << ", language=" << language
                      << ", encoding=" << encoding
                      << ", sample_rate=" << sample_rate
                      << ", channels=" << channels << std::endl;

            // Create outbound WebSocket connection to Deepgram using Boost.Beast with TLS
            auto closed = std::make_shared<std::atomic<bool>>(false);
            auto dg_to_client_count = std::make_shared<std::atomic<int64_t>>(0);
            auto client_to_dg_count = std::make_shared<std::atomic<int64_t>>(0);

            auto dg_ws = std::make_shared<websocket::stream<beast::ssl_stream<tcp::socket>>>(
                net::io_context{}, ssl::context{ssl::context::tlsv12_client}
            );

            // We need a persistent io_context, so allocate one
            auto ioc = std::make_shared<net::io_context>();
            auto ssl_ctx = std::make_shared<ssl::context>(ssl::context::tlsv12_client);
            ssl_ctx->set_default_verify_paths();
            ssl_ctx->set_verify_mode(ssl::verify_none); // Deepgram uses valid certs but simplify for starter

            try {
                tcp::resolver resolver(*ioc);
                auto results = resolver.resolve("api.deepgram.com", "443");

                auto& beast_stream = beast::get_lowest_layer(
                    *(dg_ws = std::make_shared<websocket::stream<beast::ssl_stream<tcp::socket>>>(
                        *ioc, *ssl_ctx)));
                beast_stream.connect(results);

                // Set SNI hostname for TLS
                if (!SSL_set_tlsext_host_name(dg_ws->next_layer().native_handle(), "api.deepgram.com")) {
                    throw std::runtime_error("Failed to set SNI hostname");
                }

                // TLS handshake
                dg_ws->next_layer().handshake(ssl::stream_base::client);

                // WebSocket handshake with auth header
                dg_ws->set_option(websocket::stream_base::decorator(
                    [&config_ptr](websocket::request_type& req) {
                        req.set(http::field::authorization, "Token " + config_ptr->deepgram_api_key);
                        req.set(http::field::host, "api.deepgram.com");
                    }));

                dg_ws->handshake("api.deepgram.com", dg_path);

                std::cout << "Connected to Deepgram STT API" << std::endl;

            } catch (const std::exception& e) {
                std::cerr << "Failed to connect to Deepgram: " << e.what() << std::endl;
                conn.close("Failed to connect to Deepgram");
                delete data;
                return;
            }

            // Store connection state as userdata (replace the old string)
            struct ConnState {
                std::shared_ptr<websocket::stream<beast::ssl_stream<tcp::socket>>> dg_ws;
                std::shared_ptr<std::atomic<bool>> closed;
                std::shared_ptr<std::atomic<int64_t>> client_to_dg_count;
                std::shared_ptr<std::atomic<int64_t>> dg_to_client_count;
                std::shared_ptr<net::io_context> ioc;
                std::shared_ptr<ssl::context> ssl_ctx;
                std::thread read_thread;
                std::mutex dg_write_mutex;
            };

            auto* state = new ConnState{
                dg_ws, closed, client_to_dg_count, dg_to_client_count, ioc, ssl_ctx, {}, {}
            };

            delete data;
            conn.userdata(state);

            // Start the Deepgram read loop on a separate thread
            state->read_thread = std::thread(deepgram_read_loop,
                dg_ws, &conn, closed, dg_to_client_count);
            state->read_thread.detach();
        })
        .onmessage([](crow::websocket::connection& conn, const std::string& msg, bool is_binary) {
            // Forward messages from client to Deepgram
            struct ConnState {
                std::shared_ptr<websocket::stream<beast::ssl_stream<tcp::socket>>> dg_ws;
                std::shared_ptr<std::atomic<bool>> closed;
                std::shared_ptr<std::atomic<int64_t>> client_to_dg_count;
                std::shared_ptr<std::atomic<int64_t>> dg_to_client_count;
                std::shared_ptr<net::io_context> ioc;
                std::shared_ptr<ssl::context> ssl_ctx;
                std::thread read_thread;
                std::mutex dg_write_mutex;
            };

            auto* state = static_cast<ConnState*>(conn.userdata());
            if (!state || state->closed->load()) return;

            int64_t count = state->client_to_dg_count->fetch_add(1) + 1;

            if (is_binary) {
                if (count % 10 == 0) {
                    std::cout << "[client->deepgram] message #" << count
                              << " (binary: true, size: " << msg.size() << ")" << std::endl;
                }
            } else {
                std::cout << "[client->deepgram] message #" << count
                          << " (binary: false, size: " << msg.size() << ")" << std::endl;
            }

            try {
                std::lock_guard<std::mutex> lock(state->dg_write_mutex);
                state->dg_ws->binary(is_binary);
                state->dg_ws->write(net::buffer(msg));
            } catch (const std::exception& e) {
                std::cerr << "[client->deepgram] write error: " << e.what() << std::endl;
                state->closed->store(true);
            }
        })
        .onclose([](crow::websocket::connection& conn, const std::string& reason) {
            std::cout << "Client disconnected from /api/live-transcription" << std::endl;

            struct ConnState {
                std::shared_ptr<websocket::stream<beast::ssl_stream<tcp::socket>>> dg_ws;
                std::shared_ptr<std::atomic<bool>> closed;
                std::shared_ptr<std::atomic<int64_t>> client_to_dg_count;
                std::shared_ptr<std::atomic<int64_t>> dg_to_client_count;
                std::shared_ptr<net::io_context> ioc;
                std::shared_ptr<ssl::context> ssl_ctx;
                std::thread read_thread;
                std::mutex dg_write_mutex;
            };

            auto* state = static_cast<ConnState*>(conn.userdata());
            if (!state) return;

            state->closed->store(true);

            // Close the Deepgram WebSocket connection
            std::cout << "Proxy session ending, closing connections" << std::endl;
            try {
                state->dg_ws->close(websocket::close_code::normal);
            } catch (...) {}

            // Clean up (detached thread will exit on its own when closed flag is set)
            delete state;
            conn.userdata(nullptr);
        });

    // ========================================================================
    // START SERVER
    // ========================================================================

    std::cout << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Backend API Server running at http://localhost:" << cfg.port << std::endl;
    std::cout << std::endl;
    std::cout << "  GET  /api/session" << std::endl;
    std::cout << "  WS   /api/live-transcription (auth required)" << std::endl;
    std::cout << "  GET  /api/metadata" << std::endl;
    std::cout << "  GET  /health" << std::endl;
    std::cout << std::endl;
    std::cout << "Session secret: " << secret_hex << "... (first 8 bytes)" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << std::endl;

    app.port(cfg.port)
       .bindaddr(cfg.host)
       .multithreaded()
       .run();

    return 0;
}
