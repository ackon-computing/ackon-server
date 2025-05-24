#include <memory>
#include <map>
#include <cstdint>
#include <regex>
#include <iostream>
#include <fstream>
#include <cstring>
#include <evhttp.h>
#include <sstream>

#include "json.hpp"
#include "webserver.hpp"
#include "sign.hpp"

#define SERVER_NAME "ackon-server/1.0"
//#define SERVER_POWERED "HA Solutions"

using json = nlohmann::json;

std::string urlDecode(std::string &SRC) {
    std::string ret;
    char ch;
    int i, ii;
    for (i=0; i<SRC.length(); i++) {
        if (SRC[i]=='%') {
            std::sscanf(SRC.substr(i+1,2).c_str(), "%x", &ii);
            ch=static_cast<char>(ii);
            ret+=ch;
            i=i+2;
        } else {
            ret+=SRC[i];
        }
    }
    return (ret);
}

std::map<std::string, std::string> parseParams(std::string in) {
    std::map<std::string, std::string> params;
    std::stringstream s_params(in);
    std::string pair;

    while(std::getline(s_params, pair, '&'))
    {
	std::stringstream s_pair(pair);
	std::string name, val;
	std::getline(s_pair, name, '=');
	std::getline(s_pair, val, '=');
	params.insert(std::pair<std::string, std::string>(name, urlDecode(val)));
    }
    return params;
}

void gen_random(char *s, int l) {
    for (int c; c=rand()%62, *s++ = (c+"07="[(c+16)/26])*(l-->0););
}

int startWebServer(serverenv *env) {
  if (!event_init()) {
    std::cerr << "Failed to init libevent." << std::endl;
    return -1;
  }

  char const SrvAddress[] = "0.0.0.0";
  std::uint16_t SrvPort = 8085;

  std::cout << "webserver run with urls:" << std::endl;

  std::unique_ptr<evhttp, decltype(&evhttp_free)> Server(evhttp_start(SrvAddress, SrvPort), &evhttp_free);
  if (!Server) {
    std::cerr << "Failed to init http server." << std::endl;
    return -1;
  }
  void (*OnReq)(evhttp_request *req, void *) = [] (evhttp_request *req, void *passed) {
    serverenv *env = (serverenv*)passed;
    auto *OutBuf = evhttp_request_get_output_buffer(req);
    if (!OutBuf) {
       return;
    }
    const char *query = evhttp_request_get_uri(req);
    evhttp_add_header(req->output_headers, "Server", SERVER_NAME);
//    evhttp_add_header(req->output_headers, "X-Powered-By", SERVER_POWERED);

    if (!query) {
        evhttp_send_reply(req, 404, "", OutBuf);
	return;
    }

    std::size_t pos = std::string(query).find("?");
    std::string uri = std::string(query).substr(0, pos);

    if (std::string(uri).compare("/download/list/coordinators") == 0) {
	PGresult* res = NULL;
	const char* query = "SELECT pubkey FROM coordinators_nodes WHERE pubkey IS NOT NULL;";
	res = PQexec(env->conn, query);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int nrows = PQntuples(res);
	std::string resp = "{ \"keys\": [ ";
	for (int i=0; i<nrows; i++) {
	    char* pubkey = PQgetvalue(res, i, 0);
	    if (resp.length() == std::string("{ \"keys\": [ ").length()) {
		std::string publicKey(pubkey);
		publicKey = std::regex_replace(publicKey, std::regex("\n"), "\\n");
		resp.append(" \"" + publicKey +  "\" ");
	    } else {
		std::string publicKey(pubkey);
		publicKey = std::regex_replace(publicKey, std::regex("\n"), "\\n");
		resp.append(", \"" + publicKey +  "\" ");
	    }
	}
	resp.append("]}");
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evbuffer_add_printf(OutBuf, "%s", resp.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
    } else if (std::string(uri).compare("/coordinator/login/pubkey") == 0) {
	/*
        {
            "sendpubkey": {
                "userid": userid,
                "token": token,
                "pubkey": pubkey,
            }
        }
	*/
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	json object = responseJson["sendpubkey"];
	std::string coordinatorid = object["coordinatorid"];
	std::string token = object["token"];
	std::string pubkey = object["pubkey"];

	PGresult* res = NULL;
	const char* query = "SELECT * FROM coordinators_nodes WHERE id=$1 AND token=$2;";
	const char* qparams[2];
	qparams[0] = coordinatorid.c_str();
	qparams[1] = token.c_str();
	std::cout << "Query next: " << query << " with params " << coordinatorid << " <> " << token << std::endl;
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int nrows = PQntuples(res);
	if (nrows == 1) {
	    const char* update = "UPDATE coordinators_nodes SET pubkey=$3 WHERE id=$1 AND token=$2";
	    const char* uparams[3];
	    uparams[0] = coordinatorid.c_str();
	    uparams[1] = token.c_str();
	    uparams[2] = pubkey.c_str();
	
	    res = PQexecParams(env->conn, update, 3, NULL, uparams, NULL, NULL, 0);
	    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	        std::string html = ("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
	        std::string html = ("{ \"status\":\"ok\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    std::string html = ("{ \"status\":\"token not found\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
	free(data);

    } else if (std::string(uri).compare("/coordinator/login/signin") == 0) {
	//GET parametes: login, password
        std::string params = std::string(query).substr(pos+1);
        std::map<std::string, std::string> paramsMap = parseParams(params);

	if ((paramsMap.find("login") == paramsMap.end()) ||
	    (paramsMap.find("password") == paramsMap.end())) {
	    std::string html = "Bad request (required params: login, password)";
            evbuffer_add_printf(OutBuf, "%s", html.c_str());
            evhttp_send_reply(req, 400, "", OutBuf);
	    return;
	}

	PGresult* res = NULL;
	const char* query = "SELECT * FROM coordinators_users WHERE login=$1 AND password_hash=$2;";
	const char* qparams[2];
	qparams[0] = paramsMap["login"].c_str();
	qparams[1] = paramsMap["password"].c_str();
	std::cout << query << " with params " << paramsMap["login"] << " <> " << paramsMap["password"] << std::endl;
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int ncols = PQnfields(res);
	int nrows = PQntuples(res);
	bool found=false;
	unsigned long long userid = 0;
	for(int i = 0; i < nrows; i++) {
	    char* id = PQgetvalue(res, i, 0);
	    char* login = PQgetvalue(res, i, 1);
	    char* password = PQgetvalue(res, i, 2);
	    found=true;
	    userid = atoll(id);
//	    html.append("Id: " + std::string(id) + "\n");
	}
	std::string html = "";
	if ((found) && (userid > 0)) {
	    const char* insert = "INSERT INTO coordinators_nodes (coordinators_users_id, token) VALUES ($1, $2)  RETURNING ID;";
	    char* iparams[2];
	    iparams[0] = (char*)std::to_string(userid).c_str();
	    iparams[1] = (char*)malloc(250);
	    bzero(iparams[1], 250);
	    gen_random(iparams[1], 60);
	    res = PQexecParams(env->conn, insert, 2, NULL, iparams, NULL, NULL, 0);
	    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		html.append("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
		char* nodeid = PQgetvalue(res, 0, 0);
		html.append("{ \"status\":\"ok\", \"token\":\"" +std::string(iparams[1])+ "\", \"coordinatorid\":\"" + std::string(nodeid) + "\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    html.append("{ \"status\":\"not login\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}

    } else if (std::string(uri).compare("/login/signin") == 0) {
	//GET parametes: login, password

        std::string params = std::string(query).substr(pos+1);
        std::map<std::string, std::string> paramsMap = parseParams(params);

	if ((paramsMap.find("login") == paramsMap.end()) ||
	    (paramsMap.find("password") == paramsMap.end())) {
	    std::string html = "Bad request (required params: login, password)";
            evbuffer_add_printf(OutBuf, "%s", html.c_str());
            evhttp_send_reply(req, 400, "", OutBuf);
	    return;
	}
	
	PGresult* res = NULL;
	const char* query = "SELECT * FROM users WHERE login=$1 AND password_hash=$2;";
	const char* qparams[2];
	qparams[0] = paramsMap["login"].c_str();
	qparams[1] = paramsMap["password"].c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int ncols = PQnfields(res);
	int nrows = PQntuples(res);
	bool found=false;
	unsigned long long userid = 0;
	for(int i = 0; i < nrows; i++) {
	    char* id = PQgetvalue(res, i, 0);
	    char* login = PQgetvalue(res, i, 1);
	    char* password = PQgetvalue(res, i, 2);
	    found=true;
	    userid = atoll(id);
//	    html.append("Id: " + std::string(id) + "\n");
	}
	std::string html = "";
	if ((found) && (userid > 0)) {
	    //
	    const char* insert = "INSERT INTO clients (user_id, token) VALUES ($1, $2)  RETURNING ID;";
	    char* iparams[2];
	    iparams[0] = (char*)std::to_string(userid).c_str();
	    iparams[1] = (char*)malloc(250);
	    bzero(iparams[1], 250);
	    gen_random(iparams[1], 60);
	    res = PQexecParams(env->conn, insert, 2, NULL, iparams, NULL, NULL, 0);
//	    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		html.append("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
		char* nodeid = PQgetvalue(res, 0, 0);
		html.append("{ \"status\":\"ok\", \"token\":\"" +std::string(iparams[1])+ "\", \"userid\":\"" + std::string(nodeid) + "\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    html.append("{ \"status\":\"not login\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
    } else if (std::string(uri).compare("/login/pubkey") == 0) {
	//POST json:
	/*
        {
            "sendpubkey": {
                "userid": userid,
                "token": token,
                "pubkey": pubkey,
            }
        }
	*/
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	json object = responseJson["sendpubkey"];
	std::string userid = object["userid"];
	std::string token = object["token"];
	std::string pubkey = object["pubkey"];

	PGresult* res = NULL;
	const char* query = "SELECT * FROM clients WHERE id=$1 AND token=$2;";
	const char* qparams[2];
	qparams[0] = userid.c_str();
	qparams[1] = token.c_str();
	res = PQexecParams(env->conn, query, 2, NULL, qparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db" << std::endl;
	}
	int nrows = PQntuples(res);
	if (nrows == 1) {
	    const char* update = "UPDATE clients SET pubkey=$3 WHERE id=$1 AND token=$2";
	    const char* uparams[3];
	    uparams[0] = userid.c_str();
	    uparams[1] = token.c_str();
	    uparams[2] = pubkey.c_str();
	
	    res = PQexecParams(env->conn, update, 3, NULL, uparams, NULL, NULL, 0);
	    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	        std::string html = ("{ \"status\":\"fail\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    } else {
	        std::string html = ("{ \"status\":\"ok\" }");
	        evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	        evbuffer_add_printf(OutBuf, "%s", html.c_str());
	        evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	    }
	} else {
	    std::string html = ("{ \"status\":\"token not found\" }");
	    evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	    evbuffer_add_printf(OutBuf, "%s", html.c_str());
	    evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	}
	free(data);
    } else if (std::string(uri).compare("/task/sign") == 0) {
	//POST json:
	/*
	{
	    "userid": 1,
	    "token": "...",
	    "rawtosign": "...",
	    "shards": 300,
	    "redundancy": 1
	}
	*/
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char* data = (char*)malloc(len + 1);
	bzero(data, len+1);
	evbuffer_copyout(buf, data, len);
	json responseJson = json::parse(std::string(data));
	std::string userid = responseJson["userid"];
	std::string token = responseJson["token"];
	std::string rawtosign = responseJson["rawtosign"];
	int shards = responseJson["shards"];
	int redundancy = responseJson["redundancy"];
	
	int ptu = shards * redundancy;
	char ptu_str[200] = {0};
	sprintf(ptu_str, "%d", ptu);
	
	const char* select = "SELECT user_id FROM clients WHERE id = $1";
	const char* sparams[1];
	sparams[0] = userid.c_str();
	PGresult* res = PQexecParams(env->conn, select, 1, NULL, sparams, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't select from db#1" << std::endl;
	}
	char *id = PQgetvalue(res, 0, 0);
	std::cout << id << std::endl;

	const char* update = "UPDATE users SET ptu_summ = ptu_summ - $1::int WHERE id = $2::int;";
	const char* insert = "INSERT INTO users_clients_locks (user_id, client_id, ptu_summ, locked_at) VALUES ($2::int, $3::int, $1::int, NOW()) RETURNING ID;";
	const char* params[3];
	params[0] = ptu_str;
	params[1] = id;
	params[2] = userid.c_str();
	res = PQexecParams(env->conn, update, 2, NULL, params, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	    std::cout << "Can't update in db#1.5" << std::endl;
	}
	res = PQexecParams(env->conn, insert, 3, NULL, params, NULL, NULL, 0);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
	    std::cout << "Can't insert in db#2" << std::endl;
	}
	char *taskid = PQgetvalue(res, 0, 0);
	rawtosign.append("taskid=" + std::string(taskid) + "\n");
	
	std::string signd = std::regex_replace(sign(rawtosign), std::regex("\n"), "\\n");
//	std::string signd = sign(rawtosign)
	std::string html = ("{ \"status\":\"ok\", \"task-id\":\"" + std::string(taskid) + "\", \"sign\":\""+signd+"\" }");
	evhttp_add_header(req->output_headers, "Content-Type", "application/json");
	evbuffer_add_printf(OutBuf, "%s", html.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf);
	/*
rawtosign:
	rawtosign = (format["task"]["attached-files-hashes"]["Dockerfile"] + "\n" +
	            format["task"]["attached-files-hashes"]["upload.creds"] + "\n" +
	        format["task"]["attached-files-hashes"]["scaling.yaml"] + "\n" +
	            format["task"]["attached-files-hashes"]["duplication.yaml"] + "\n" +
	            format["task"]["attached-files-hashes"]["urls_list"]["hash"] + "\n" );
	for key, value in format["task"]["unsigned"]["attached-files-raw"]["others"]:
	    rawtosign = (rawtosign + value + "\n")
	rawtosign = (rawtosign + "mode=" + format["task"]["mode"] + "\n")
	rawtosign = (rawtosign + "userid=" + user["userid"] + "\n")
	*/

	//calculate shards*redundancy, lock 300 PTU from user to taskid (and generate taskid)
	//append to rawtosign: "taskid=123\n"
	//sign(rawtosign)
	//response:
	/*
	    { "taskid": 123,
	      "server-signature": "..."
	*/
	
	/* std::string html = "Hello on /task/sign!\n\n";
	evbuffer_add_printf(OutBuf, "%s", html.c_str());
	evhttp_send_reply(req, HTTP_OK, "", OutBuf); */
    } else {
        if (query) {
            evbuffer_add_printf(OutBuf, "<html><body><center><h1>Not found</h1></center></body></html>");
        }
        evhttp_send_reply(req, 404, "", OutBuf);
    }


//    evbuffer_free(OutBuf);
  };
  evhttp_set_gencb(Server.get(), OnReq, env);
  if (event_dispatch() == -1) {
    std::cerr << "Failed to run messahe loop." << std::endl;
    return -1;
  }
  return 0;
}
