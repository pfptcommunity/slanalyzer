/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
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
  friend class Analyzer;
 public:
  enum class FieldType {
	UNKNOWN, IP, HOST, HELO, RCPT, FROM, HFROM
  };
  enum class MatchType {
	UNKNOWN, EQUAL, NOT_EQUAL, MATCH, NOT_MATCH, REGEX, NOT_REGEX, IP_IN_NET, IP_NOT_IN_NET, IS_IN_DOMAINSET
  };
  struct Entry {
	FieldType field_type;
	MatchType match_type;
	std::string pattern;
	std::string comment;
	uint32_t matches;
  };
 public:
  static FieldType GetFieldType(const std::string &field);
  static std::string GetFieldTypeString(FieldType field);
  static MatchType GetMatchType(const std::string &field);
  static std::string GetMatchTypeString(MatchType matchtype);
 public:
  SafeList() = default;;
  void Load(const std::string &list_file);
  void Save(const std::string &list_file);
 private:
  std::vector<std::shared_ptr<Entry>> safe_list;
};
typedef SafeList::MatchType SBMatchType;
typedef SafeList::FieldType SBFieldType;
}
#endif //SLPARSER_SAFELIST_H
