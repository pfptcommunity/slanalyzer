/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slparser
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLPARSER_SAFELIST_H
#define SLPARSER_SAFELIST_H
#include <string>
#include <memory>
#include <vector>

namespace Proofpoint {
class SafeList {
  friend class Processor;
 public:
  enum class SBFieldType {
	UNKNOWN, IP, HOST, HELO, RCPT, FROM, HFROM
  };
  enum class SBMatchType {
	UNKNOWN, EQUAL, NOT_EQUAL, MATCH, NOT_MATCH, REGEX, NOT_REGEX, IP_IN_NET, IP_NOT_IN_NET, IS_IN_DOMAINSET
  };
  struct SLEntry {
	SBFieldType field_type;
	SBMatchType match_type;
	std::string pattern;
	std::string comment;
	uint32_t matches;
  };
 public:
  static SBFieldType GetFieldType(const std::string &field);
  static std::string GetFieldTypeString(SBFieldType field);
  static SBMatchType GetMatchType(const std::string &field);
  static std::string GetMatchTypeString(SBMatchType matchtype);
 public:
  SafeList() = default;;
  void Load(const std::string &list_file);
  void Save(const std::string &list_file);
 private:
  std::vector<std::shared_ptr<SLEntry>> safe_list;
};
}
#endif //SLPARSER_SAFELIST_H
