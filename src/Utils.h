/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_SRC_UTILS_H_
#define SLPARSER_SRC_UTILS_H_

#include <string>
#include <map>

namespace Proofpoint {
namespace Utils {
static inline void ltrim(std::string &s) {
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
	return !std::isspace(ch);
  }));
}

static inline void rtrim(std::string &s) {
  s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
	return !std::isspace(ch);
  }).base(), s.end());
}

static inline void trim(std::string &s) {
  rtrim(s);
  ltrim(s);
}

static inline std::string ltrim_copy(std::string s) {
  ltrim(s);
  return s;
}

static inline std::string rtrim_copy(std::string s) {
  rtrim(s);
  return s;
}

static inline std::string trim_copy(std::string s) {
  trim(s);
  return s;
}
}
}

#endif //SLPARSER_SRC_UTILS_H_
