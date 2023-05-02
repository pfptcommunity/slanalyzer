/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_UTILS_H
#define SLANALYZER_UTILS_H

#include <string>
#include <vector>
#include <string_view>

namespace Proofpoint::Utils {
void reverse(std::string& str);
void ltrim(std::string& str);
void rtrim(std::string& str);
void trim(std::string& str);
std::string reverse_copy(std::string s);
std::string ltrim_copy(std::string s);
std::string rtrim_copy(std::string s);
std::string trim_copy(std::string s);
std::vector<std::string_view> split(std::string_view str, char d);
}

#endif //SLANALYZER_UTILS_H
