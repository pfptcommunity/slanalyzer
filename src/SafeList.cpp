#include "SafeList.h"
#include "csvparser.h"
#include <iostream>
#include <iomanip>
#include <chrono>

void Proofpoint::SafeList::Load(const std::string &list_file) {
  using std::chrono::high_resolution_clock;
  using std::chrono::microseconds;
  auto start = high_resolution_clock::now();
  std::ifstream f(list_file);
  csv::CsvParser parser(f);
  for (auto &row : parser) {
	size_t cols = row.size();
	SBFieldType ft = (cols > 0) ? GetFieldType(row.at(0)) : SBFieldType::UNKNOWN;
	SBMatchType mt = (cols > 1) ? GetMatchType(row.at(1)) : SBMatchType::UNKNOWN;
	if (ft==SBFieldType::UNKNOWN || mt==SBMatchType::UNKNOWN) continue;
	safe_list.push_back(std::make_shared<SLEntry>());
	safe_list.back()->field_type = ft;
	safe_list.back()->match_type = mt;
	safe_list.back()->pattern = (cols > 2) ? row.at(2) : "";
	safe_list.back()->comment = (cols > 3) ? row.at(3) : "";
	safe_list.back()->matches = 0;
  }
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  std::cout << std::right << std::setw(25) << "SL Load Completed: "
			<< std::left << std::setw(25) << std::to_string(duration.count()) + "μs"
			<< std::setw(10) << std::setprecision(2)
			<< "[" + std::to_string((double)duration.count()/1000000) + "s]" << "[" << list_file << "]"
			<< std::endl;
}
void Proofpoint::SafeList::Save(const std::string &list_file) {
  using std::chrono::high_resolution_clock;
  using std::chrono::microseconds;
  auto start = high_resolution_clock::now();
  const char delim{'"'};
  const char escape{'"'};
  std::ofstream f(list_file);
  f << std::quoted("FieldType", delim, escape)
	<< "," << std::quoted("MatchType", delim, escape)
	<< "," << std::quoted("Pattern", delim, escape)
	<< "," << std::quoted("Comment", delim, escape)
	<< "," << std::quoted("Matches", delim, escape) << std::endl;
  for (const auto &list_entry : safe_list) {
	f << std::quoted(GetFieldTypeString(list_entry->field_type), delim, escape)
	  << "," << std::quoted(GetMatchTypeString(list_entry->match_type), delim, escape)
	  << "," << std::quoted(list_entry->pattern, delim, escape)
	  << "," << std::quoted(list_entry->comment, delim, escape)
	  << "," << std::quoted(std::to_string(list_entry->matches), delim, escape) << std::endl;
  }
  auto stop = high_resolution_clock::now();
  auto duration = duration_cast<microseconds>(stop - start);
  std::cout << std::right << std::setw(25) << "SL Save Completed: "
			<< std::left << std::setw(25) << std::to_string(duration.count()) + "μs"
			<< std::setw(10) << std::setprecision(2)
			<< "[" + std::to_string((double)duration.count()/1000000) + "s]" << "[" << list_file << "]"
			<< std::endl;
}
Proofpoint::SafeList::SBFieldType Proofpoint::SafeList::GetFieldType(const std::string &field) {
  using
  enum SBFieldType;
  if (field=="$ip")
	return IP;
  if (field=="$host")
	return HOST;
  if (field=="$helo")
	return HELO;
  if (field=="$rcpt")
	return RCPT;
  if (field=="$from")
	return FROM;
  if (field=="$hfrom")
	return HFROM;
  return UNKNOWN;
}
std::string Proofpoint::SafeList::GetFieldTypeString(Proofpoint::SafeList::SBFieldType field) {
  using
  enum SBFieldType;
  switch (field) {
	case IP: return "$ip";
	  break;
	case HOST: return "$host";
	  break;
	case HELO: return "$helo";
	  break;
	case RCPT: return "$rcpt";
	  break;
	case FROM: return "$from";
	  break;
	case HFROM: return "$hfrom";
	  break;
	default: return "unknown";
	  break;
  }
}
Proofpoint::SafeList::SBMatchType Proofpoint::SafeList::GetMatchType(const std::string &field) {
  if (field=="equal")
	return SBMatchType::EQUAL;
  else if (field=="not_equal")
	return SBMatchType::NOT_EQUAL;
  else if (field=="match")
	return SBMatchType::MATCH;
  else if (field=="not_match")
	return SBMatchType::NOT_MATCH;
  else if (field=="regex")
	return SBMatchType::REGEX;
  else if (field=="not_regex")
	return SBMatchType::NOT_REGEX;
  else if (field=="ip_in_net")
	return SBMatchType::IP_IN_NET;
  else if (field=="ip_not_in_net")
	return SBMatchType::IP_NOT_IN_NET;
  else if (field=="is_in_domainset")
	return SBMatchType::IS_IN_DOMAINSET;
  else
	return SBMatchType::UNKNOWN;
}
std::string Proofpoint::SafeList::GetMatchTypeString(Proofpoint::SafeList::SBMatchType matchtype) {
  using
  enum SBMatchType;
  switch (matchtype) {
	case EQUAL: return "equal";
	  break;
	case NOT_EQUAL: return "not_equal";
	  break;
	case MATCH: return "match";
	  break;
	case NOT_MATCH: return "not_match";
	  break;
	case REGEX: return "regex";
	  break;
	case NOT_REGEX: return "not_regex";
	  break;
	case IP_IN_NET: return "ip_in_net";
	  break;
	case IP_NOT_IN_NET: return "ip_not_in_net";
	  break;
	case IS_IN_DOMAINSET: return "is_in_domainset";
	  break;
	default: return "unknown";
	  break;
  }
}
