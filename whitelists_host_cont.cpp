#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <unordered_set>


int main(int argc, char *argv[]) {

    if (argc < 3) {
        std::cerr << "The program needs the following arguments:" << std::endl
                  << "1) an integer: the position of file-hash (starting by zero) in the current ML's template;" << std::endl
                  << "2) an integer: the position of file-path (starting by zero) in the current ML's template;" << std::endl
                  << "3) an integer (optional): the position of pids (starting by zero) in the current ML's template;" << std::endl
         	  << "4) an integer (optional): the position of cgn (starting by zero) in the current ML's template;" << std::endl
         	  << "5) a string (optional): the containers' dependency path;" << std::endl
         	  << "6) a integer (optional): the containers' dependency pid position (starting by pid==0, counting by zero)." << std::endl;         
        return 1;
    }

    int filehash_pos = std::stoi(argv[1]);
    int filepath_pos = std::stoi(argv[2]);
    int pids_pos = -1;
    int cgn_pos = -1;
    std::string cont_dependency;
    int cont_dep_pid_pos = -1;
    if (argc == 7) {
        pids_pos = std::stoi(argv[3]);
        cgn_pos = std::stoi(argv[4]);
        cont_dependency.assign(argv[5]);
        cont_dep_pid_pos = std::stoi(argv[6]);
    }

    std::ifstream ifs{"/sys/kernel/security/ima/ascii_runtime_measurements", std::ios_base::in};
    if (!ifs) {
        std::cerr << "It's not possible to open \"ascii_runtime_measurements\" for reading.";
        return 1;
    }

    std::ofstream host_ofs{"allowlist_host", std::ios_base::app};
    if (!host_ofs) {
        std::cerr << "It's not possible to open \"allowlist_host\" for writing in append mode.";
        return 2;
    }
    /*hash_map with key= contID, value= allowlist*/
    std::unordered_map<std::string, std::unordered_map<std::string, std::unordered_set<std::string>>> containers_allowlists{};
    /*hash_map for host's allowlist with key= file_path, value= hash_set of file_hash*/
    std::unordered_map<std::string, std::unordered_set<std::string>> host_allowlist{};
    
    std::unordered_set<std::string> cont_dependency_pids{};

    std::string line{};

    while (std::getline(ifs, line)) {
        std::vector<std::string> entry_tokens;

        std::istringstream line_stream{line};

        std::string t;

        // Tokenizing w.r.t. delimiter ' '
        while (std::getline(line_stream, t, ' ')) {
            entry_tokens.push_back(t);
        }

        if (filehash_pos >= entry_tokens.size()) {
            std::cerr << "The position of file-hash provided as first command-line parameter is not compatible with the current line: " << line << std::endl;
            return 3;
        } else if (filepath_pos >= entry_tokens.size()) {
            std::cerr << "The position of file-path provided as second command-line parameter is not compatible with the current line: " << line << std::endl;
            return 3;
        } else if (cgn_pos >= entry_tokens.size()) {
            std::cerr << "The position of cgn provided as third command-line parameter is not compatible with the current line: " << line << std::endl;
            return 3;
        } else if (pids_pos >= entry_tokens.size()) {
            std::cerr << "The position of pids provided as fourth command-line parameter is not compatible with the current line: " << line << std::endl;
            return 3;
        } 


        std::vector<std::string> filehash_tokens;

        std::istringstream filehash_stream{entry_tokens[filehash_pos]};
        // Tokenizing w.r.t. delimiter ':'
        while (std::getline(filehash_stream, t, ':')) {
            filehash_tokens.push_back(t);
        }

        if (pids_pos >= 0 && cgn_pos >= 0 && cont_dep_pid_pos >= 0) {
        	if (!entry_tokens[filepath_pos].compare(cont_dependency)) {
			std::string pid_str;
			std::istringstream pids_stream{entry_tokens[pids_pos]};
			std::getline(pids_stream, pid_str, '-');
			cont_dependency_pids.insert(pid_str);
		}
        	
        	std::string dep_pid_str;
        	std::istringstream pids_stream{entry_tokens[pids_pos]};
        	std::vector<std::string> pids_vec;
        	while (std::getline(pids_stream, dep_pid_str, '-')) 
        		pids_vec.push_back(dep_pid_str);
        	
		std::string cgn = entry_tokens[cgn_pos];
		if (cgn.size() == 64 && cgn.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos && (pids_vec.size()-1-cont_dep_pid_pos >= 0) && cont_dependency_pids.count(pids_vec[pids_vec.size()-1-cont_dep_pid_pos]) > 0) {
			std::string contID = cgn.substr(0, 12);
			containers_allowlists[contID][entry_tokens[filepath_pos]].insert(filehash_tokens[1]);
			continue;
		}
        }

        host_allowlist[entry_tokens[filepath_pos]].insert(filehash_tokens[1]);
    }
    
    for (auto it1 = host_allowlist.begin(); it1 != host_allowlist.end(); it1++) {
    	for (auto it2 = it1->second.begin(); it2 != it1->second.end(); it2++)
    		host_ofs << (*it2) << "  " << it1->first << std::endl;
    }
    
    for (auto it1 = containers_allowlists.begin(); it1 != containers_allowlists.end(); it1++) {
    	std::ofstream cont_ofs{"allowlist_" + it1->first, std::ios_base::app};
    	if (!cont_ofs) {
		std::cerr << "It's not possible to open \"allowlist_" << it1->first << "\" for writing in append mode.";
		return 2;
    	}
    	for (auto it2 = it1->second.begin(); it2 != it1->second.end(); it2++)
    		for (auto it3 = it2->second.begin(); it3 != it2->second.end(); it3++)
    			cont_ofs << (*it3) << "  " << it2->first << std::endl;
    }
    
    std::ofstream cont_list_ofs{"containers_list", std::ios_base::out};
    if (!cont_list_ofs) {
	std::cerr << "It's not possible to open \"containers_list\" for writing.";
	return 2;
    }
    for (auto it1 = containers_allowlists.begin(); it1 != containers_allowlists.end(); it1++) 
    	cont_list_ofs << it1->first << " " << "./allowlist_" << it1->first << std::endl;

    return 0;
}

                
                
                
                
                
                
