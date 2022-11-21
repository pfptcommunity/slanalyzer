/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "GlobalList.h"
#include "CsvParser.h"
#include <iostream>
#include <utility>
#include <chrono>
#include "re2/re2.h"
#include <numeric>

void Proofpoint::GlobalList::Load(const std::string& list_file, EntryErrors& entry_errors )
{
	std::size_t count = 0;
	std::ifstream f(list_file);
	csv::CsvParser parser(f);
	for (auto& row : parser) {
		size_t cols = row.size();
		FieldType ft = (cols>0) ? GetFieldType(row.at(0)) : FieldType::UNKNOWN;
		MatchType mt = (cols>1) ? GetMatchType(row.at(1)) : MatchType::UNKNOWN;

		if ( cols > 1 && (ft==FieldType::UNKNOWN || mt==MatchType::UNKNOWN) ) {
			// We are missing something.
			entry_errors.push_back({count,
									(cols>0) ? row.at(0) : "",
									(cols>1) ? row.at(1) : "",
									"Please see field type and match type information"});
		}
		entries.emplace_back();
		entries.back().field_type = ft;
		entries.back().match_type = mt;
		if (cols>2) entries.back().pattern = row.at(2);
		if (cols>3) entries.back().comment = row.at(3);
		entries.back().inbound = 0;
		entries.back().outbound = 0;
		count++;
	}
}
void Proofpoint::GlobalList::Save(const std::string& list_file)
{
	std::size_t count = 0;
	RE2 quoted("\"");
	const char delim{'"'};
	const char escape{'"'};
	std::ios_base::sync_with_stdio(false);
	std::ofstream f(list_file);
	f << "\"" << "FieldType"
	  << "\",\"" << "MatchType"
	  << "\",\"" << "Pattern"
	  << "\",\"" << "Comment"
	  << "\",\"" << "Inbound"
	  << "\",\"" << "Outbound" << "\"\r\n";
	for (auto& list_entry : entries) {
		// Replaced for std::quoted() to improve speed
		RE2::GlobalReplace(&list_entry.pattern, quoted, "\"\"");
		RE2::GlobalReplace(&list_entry.comment, quoted, "\"\"");
		f << "\"" << FieldTypeStrings[static_cast<int>(list_entry.field_type)]
		  << "\",\"" << MatchTypeStrings[static_cast<int>(list_entry.match_type)]
		  << "\",\"" << list_entry.pattern
		  << "\",\"" << list_entry.comment
		  << "\",\"" << std::to_string(list_entry.inbound)
		  << "\",\"" << std::to_string(list_entry.outbound) << "\"\r\n";
		count++;
	}
}
inline Proofpoint::GlobalList::FieldType Proofpoint::GlobalList::GetFieldType(const std::string& field)
{
	if (strcmp("$ip", field.c_str())==0)
		return FieldType::IP;
	if (strcmp("$host", field.c_str())==0)
		return FieldType::HOST;
	if (strcmp("$helo", field.c_str())==0)
		return FieldType::HELO;
	if (strcmp("$rcpt", field.c_str())==0)
		return FieldType::RCPT;
	if (strcmp("$from", field.c_str())==0)
		return FieldType::FROM;
	if (strcmp("$hfrom", field.c_str())==0)
		return FieldType::HFROM;
	return FieldType::UNKNOWN;
}

inline const std::string& Proofpoint::GlobalList::GetFieldTypeString(Proofpoint::GlobalList::FieldType field)
{
	return FieldTypeStrings[static_cast<int>(field)];
}

inline Proofpoint::GlobalList::MatchType Proofpoint::GlobalList::GetMatchType(const std::string& field)
{
	// strcmp has consistently better times than string.compare or ==
	if (strcmp("equal", field.c_str())==0)
		return MatchType::EQUAL;
	else if (strcmp("not_equal", field.c_str())==0)
		return MatchType::NOT_EQUAL;
	else if (strcmp("match", field.c_str())==0)
		return MatchType::MATCH;
	else if (strcmp("not_match", field.c_str())==0)
		return MatchType::NOT_MATCH;
	else if (strcmp("regex", field.c_str())==0)
		return MatchType::REGEX;
	else if (strcmp("not_regex", field.c_str())==0)
		return MatchType::NOT_REGEX;
	else if (strcmp("ip_in_net", field.c_str())==0)
		return MatchType::IP_IN_NET;
	else if (strcmp("ip_not_in_net", field.c_str())==0)
		return MatchType::IP_NOT_IN_NET;
	else if (strcmp("is_in_domainset", field.c_str())==0)
		return MatchType::IS_IN_DOMAINSET;
	else
		return MatchType::UNKNOWN;
}
inline const std::string& Proofpoint::GlobalList::GetMatchTypeString(Proofpoint::GlobalList::MatchType matchtype)
{
	return MatchTypeStrings[static_cast<int>(matchtype)];
}
std::size_t Proofpoint::GlobalList::GetInboundCount() const
{
	return std::accumulate(entries.begin(), entries.end(), 0, [](const std::size_t& a, const Entry& b) -> std::size_t {return a + b.inbound;} );
}
std::size_t Proofpoint::GlobalList::GetOutboundCount() const
{
	return std::accumulate(entries.begin(), entries.end(), 0, [](const std::size_t& a, const Entry& b) -> std::size_t {return a + b.outbound;} );
}
