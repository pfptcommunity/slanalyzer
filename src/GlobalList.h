/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_SAFELIST_H
#define SLANALYZER_SAFELIST_H
#include <string>
#include <memory>
#include <vector>

namespace Proofpoint {
class GlobalList {
	friend class GlobalAnalyzer;
public:
	enum class FieldType {
	  UNKNOWN,
	  IP,
	  HOST,
	  HELO,
	  RCPT,
	  FROM,
	  HFROM
	};
	enum class MatchType {
	  UNKNOWN,
	  EQUAL,
	  NOT_EQUAL,
	  MATCH,
	  NOT_MATCH,
	  REGEX,
	  NOT_REGEX,
	  IP_IN_NET,
	  IP_NOT_IN_NET,
	  IS_IN_DOMAINSET
	};
	struct Entry {
	  std::size_t line_number;
	  FieldType field_type;
	  MatchType match_type;
	  std::string pattern;
	  std::string comment;
	  uint32_t inbound;
	  uint32_t outbound;
	};
	using Entries = std::vector<Entry>;
	struct EntryError {
	  std::size_t line;
	  std::string field_data;
	  std::string match_data;
	  std::string error;
	};
	using EntryErrors = std::vector<EntryError>;
	using iterator = Entries::iterator;
	using const_iterator = Entries::const_iterator;
public:
	static FieldType GetFieldType(const std::string& field);
	static const std::string& GetFieldTypeString(FieldType field);
	static MatchType GetMatchType(const std::string& field);
	static const std::string& GetMatchTypeString(MatchType matchtype);
private:
	inline static const std::string FieldTypeStrings[] = {"unknown", "$ip", "$host", "$helo", "$rcpt", "$from", "$hfrom"};
	inline static const std::string MatchTypeStrings[] = {"unknown", "equal", "not_equal", "match", "not_match", "regex", "not_regex", "ip_in_net", "ip_not_in_net", "is_in_domainset"};
public:
	GlobalList() = default;
	void Load(const std::string& list_file, EntryErrors& entry_errors);
	void Save(const std::string& list_file);
public:
	[[nodiscard]] inline std::size_t GetCount() const { return entries.size(); }
	[[nodiscard]] std::size_t GetInboundCount() const;
	[[nodiscard]] std::size_t GetOutboundCount() const;
	iterator begin() { return entries.begin(); }
	iterator end() { return entries.end(); }
	[[nodiscard]] const_iterator begin() const { return entries.begin(); }
	[[nodiscard]] const_iterator end() const { return entries.end(); }
	[[nodiscard]] const_iterator cbegin() const { return entries.cbegin(); }
	[[nodiscard]] const_iterator cend() const { return entries.cend(); }
private:
	Entries entries;
};
}
#endif //SLANALYZER_SAFELIST_H
