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
#include <iostream>
#include <utility>
#include <iomanip>
#include <chrono>
#include "re2/re2.h"

void Proofpoint::SafeList::Load(const std::string& list_file)
{
	std::size_t count = 0;
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
		if (cols>2) safe_list.back()->pattern = row.at(2);
		if (cols>3) safe_list.back()->comment = row.at(3);
		safe_list.back()->inbound = 0;
		safe_list.back()->outbound = 0;
		count++;
	}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << std::setw(25) << "SL Load Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << list_file << std::endl;
}
void Proofpoint::SafeList::Save(const std::string& list_file)
{
	std::size_t count = 0;
	RE2 quoted("\"");
	const char delim{'"'};
	const char escape{'"'};

	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ios_base::sync_with_stdio(false);
	std::ofstream f(list_file);
	f << "\"" << "FieldType"
	  << "\",\"" << "MatchType"
	  << "\",\"" << "Pattern"
	  << "\",\"" << "Comment"
	  << "\",\"" << "Inbound"
	  << "\",\"" << "Outbound" << "\"\r\n";
	for (const auto& list_entry : safe_list) {
		// Replaced for std::quoted() to improve speed
		RE2::GlobalReplace(&list_entry->pattern, quoted, "\"\"");
		RE2::GlobalReplace(&list_entry->comment, quoted, "\"\"");
		f << "\"" << FieldTypeStrings[static_cast<int>(list_entry->field_type)]
		  << "\",\"" << MatchTypeStrings[static_cast<int>(list_entry->match_type)]
		  << "\",\"" << list_entry->pattern
		  << "\",\"" << list_entry->comment
		  << "\",\"" << std::to_string(list_entry->inbound)
		  << "\",\"" << std::to_string(list_entry->outbound) << "\"\r\n";
		count++;
	}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::ios_base::sync_with_stdio(true);
	std::cout << std::left << std::setw(25) << "SL Save Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << list_file << std::endl;
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

inline const std::string& Proofpoint::SafeList::GetFieldTypeString(Proofpoint::SafeList::FieldType field)
{
	return FieldTypeStrings[static_cast<int>(field)];
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
inline const std::string& Proofpoint::SafeList::GetMatchTypeString(Proofpoint::SafeList::MatchType matchtype)
{
	return MatchTypeStrings[static_cast<int>(matchtype)];
}
