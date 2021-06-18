#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_set>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "The program needs, as parameter, the position (starting by zero) of the file path in the current ima template." << std::endl;
        return 1;
    }

    std::ofstream ml_analysis_ofs{"ML_analysis", std::ios_base::trunc};
    if (!ml_analysis_ofs) {
        std::cerr << "It's not possible to open \"ML_analysis\" for writing in truncate mode.";
        return 2;
    }

    int filepath_pos = std::stoi(argv[1]);
    if (filepath_pos < 0) {
        std::cerr << "The path position in the ima template must be a positive integer.";
        return 2;
    }

    std::ifstream ml_ifs{"/sys/kernel/security/ima/ascii_runtime_measurements", std::ios_base::in};
    if (!ml_ifs) {
        std::cerr << "It's not possible to open \"ascii_runtime_measurements\" for reading.";
        return 1;
    }

    std::string line{};
    std::unordered_set<std::string> dir_set{};

    while (std::getline(ml_ifs, line)) {
        std::vector<std::string> line_tokens;
        std::istringstream line_stream{line};

        std::string t;
        // Tokenizing w.r.t. delimiter ' '
        while (std::getline(line_stream, t, ' ')) {
            line_tokens.push_back(t);
        }

        if (filepath_pos >= line_tokens.size()) {
            std::cerr << "The path position parameter is not compatible with the number of fields of the current ima template.";
            return 2;
        }

        std::size_t slash_pos = line_tokens[filepath_pos].rfind("/");
        if (slash_pos != std::string::npos)
            dir_set.emplace(line_tokens[filepath_pos].begin(), line_tokens[filepath_pos].begin()+slash_pos+1);
        else
            dir_set.insert(line_tokens[filepath_pos]);
    }

    for (auto it = dir_set.begin(); it != dir_set.end(); ++it ) {
        ml_analysis_ofs << *it << std::endl;
    }

    return 0;
}
