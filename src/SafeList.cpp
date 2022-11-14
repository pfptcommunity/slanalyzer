/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "SafeList.h"
#include "CsvParser.h"
#include <cstring>
#include <iostream>
#include <iomanip>
#include <chrono>

void Proofpoint::SafeList::Load(const std::string& list_file)
{
	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ifstream f(list_file);
	csv::CsvParser parser(f);
	for (auto& row : parser) {
		size_t cols = row.size();
		FieldType ft = (cols>0) ? GetFieldType(row.at(0)) : FieldType::UNKNOWN;
		MatchType mt = (cols>1) ? GetMatchType(row.at(1)) : MatchType::UNKNOWN;
		if (ft==FieldType::UNKNOWN || mt==MatchType::UNKNOWN) continue;
		safe_list.push_back(std::make_shared<Entry>());
		safe_list.back()->field_type = ft;
		safe_list.back()->match_type = mt;
		safe_list.back()->pattern = (cols>2) ? row.at(2) : "";
		safe_list.back()->comment = (cols>3) ? row.at(3) : "";
		safe_list.back()->matches = 0;
		//safe_list.back()->inbound = 0;
		//safe_list.back()->outbound = 0;
	}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::right << std::setw(25) << "SL Load Completed: "
			  << std::left << std::setw(25) << std::to_string(duration.count())+"μs"
			  << std::setw(10) << std::setprecision(2)
			  << "["+std::to_string((double)duration.count()/1000000)+"s]" << "[" << list_file << "]"
			  << std::endl;
}
void Proofpoint::SafeList::Save(const std::string& list_file)
{
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
	for (const auto& list_entry : safe_list) {
		f << std::quoted(GetFieldTypeString(list_entry->field_type), delim, escape)
		  << "," << std::quoted(GetMatchTypeString(list_entry->match_type), delim, escape)
		  << "," << std::quoted(list_entry->pattern, delim, escape)
		  << "," << std::quoted(list_entry->comment, delim, escape)
		  << "," << std::quoted(std::to_string(list_entry->matches), delim, escape) << std::endl;
	}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::right << std::setw(25) << "SL Save Completed: "
			  << std::left << std::setw(25) << std::to_string(duration.count())+"μs"
			  << std::setw(10) << std::setprecision(2)
			  << "["+std::to_string((double)duration.count()/1000000)+"s]" << "[" << list_file << "]"
			  << std::endl;
}
inline Proofpoint::SafeList::FieldType Proofpoint::SafeList::GetFieldType(const std::string& field)
{
	if (strcmp("$ip",field.c_str()) == 0)
		return FieldType::IP;
	if (strcmp("$host",field.c_str()) == 0)
		return FieldType::HOST;
	if (strcmp("$helo",field.c_str()) == 0)
		return FieldType::HELO;
	if (strcmp("$rcpt",field.c_str()) == 0)
		return FieldType::RCPT;
	if (strcmp("$from",field.c_str()) == 0)
		return FieldType::FROM;
	if (strcmp("$hfrom",field.c_str()) == 0)
		return FieldType::HFROM;
	return FieldType::UNKNOWN;
}

inline std::string Proofpoint::SafeList::GetFieldTypeString(Proofpoint::SafeList::FieldType field)
{
	switch (field) {
	case FieldType::IP: return "$ip";
		break;
	case FieldType::HOST: return "$host";
		break;
	case FieldType::HELO: return "$helo";
		break;
	case FieldType::RCPT: return "$rcpt";
		break;
	case FieldType::FROM: return "$from";
		break;
	case FieldType::HFROM: return "$hfrom";
		break;
	default: return "unknown";
		break;
	}
}
inline Proofpoint::SafeList::MatchType Proofpoint::SafeList::GetMatchType(const std::string& field)
{
	// strcmp has consistently better times than string.compare or ==
	if (strcmp("equal",field.c_str()) == 0)
		return MatchType::EQUAL;
	else if (strcmp("not_equal",field.c_str()) == 0)
		return MatchType::NOT_EQUAL;
	else if (strcmp("match",field.c_str()) == 0)
		return MatchType::MATCH;
	else if (strcmp("not_match",field.c_str()) == 0)
		return MatchType::NOT_MATCH;
	else if (strcmp("regex",field.c_str()) == 0)
		return MatchType::REGEX;
	else if (strcmp("not_regex",field.c_str()) == 0)
		return MatchType::NOT_REGEX;
	else if (strcmp("ip_in_net",field.c_str()) == 0)
		return MatchType::IP_IN_NET;
	else if (strcmp("ip_not_in_net",field.c_str()) == 0)
		return MatchType::IP_NOT_IN_NET;
	else if (strcmp("is_in_domainset",field.c_str()) == 0)
		return MatchType::IS_IN_DOMAINSET;
	else
		return MatchType::UNKNOWN;
}
inline std::string Proofpoint::SafeList::GetMatchTypeString(Proofpoint::SafeList::MatchType matchtype)
{
	switch (matchtype) {
	case MatchType::EQUAL: return "equal";
		break;
	case MatchType::NOT_EQUAL: return "not_equal";
		break;
	case MatchType::MATCH: return "match";
		break;
	case MatchType::NOT_MATCH: return "not_match";
		break;
	case MatchType::REGEX: return "regex";
		break;
	case MatchType::NOT_REGEX: return "not_regex";
		break;
	case MatchType::IP_IN_NET: return "ip_in_net";
		break;
	case MatchType::IP_NOT_IN_NET: return "ip_not_in_net";
		break;
	case MatchType::IS_IN_DOMAINSET: return "is_in_domainset";
		break;
	default: return "unknown";
		break;
	}
}
