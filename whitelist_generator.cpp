#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <filesystem>

#include <openssl/sha.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "The program needs the path of the folder to use for calculating the whitelist as argument." << std::endl;
        return 1;
    }

    std::string path{argv[1]};
    std::ofstream whitelist_ofs{"whitelist", std::ios_base::app};
    if (!whitelist_ofs) {
        std::cerr << "It's not possible to open \"whitelist\" for writing in append mode.";
        return 2;
    }

    for (const auto & entry : std::filesystem::recursive_directory_iterator(path)){
        std::ifstream file_stream{entry.path(), std::ios::binary};
        if (!file_stream) {
            std::cerr << "It's not possible to open \"" << entry.path() << "\" for calculating hash, ignoring ...";
            continue;
        }

        char byte;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        while (file_stream.read(&byte, 1)) {
            SHA256_Update(&sha256, &byte, 1);
        }
        SHA256_Final(hash, &sha256);

        std::stringstream ss;
        for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }

        whitelist_ofs << ss.str() << " " << entry.path().string() << std::endl;

    }

}
