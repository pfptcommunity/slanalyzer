/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "UserSafeList.h"
#include "CsvParser.h"
#include <iostream>
#include <utility>
#include <iomanip>
#include <numeric>
#include <chrono>
#include "re2/re2.h"
#include "Utils.h"

void Proofpoint::UserSafeList::Load(const std::string& user_file, UserErrors& entry_errors)
{
	std::size_t count = 0;
	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ifstream f(user_file);
	csv::CsvParser parser(f);
	csv::HeaderMap header_map;
	csv::HeaderList required_headers{
			"mailLocalAddress",
			"safelist",
			"blocklist",
			"givenName",
			"sn",
			"mail"};

	// Validate there are headers we are interested in...
	csv::HeaderIndex header_index = parser.FindHeader(required_headers, header_map);

	if (header_index!=-1)
		for (const auto& row : parser) {
			user_list.push_back(std::make_shared<UserEntry>());
			user_list.back()->fname = row[header_map.find("givenName")->second];
			user_list.back()->lname = row[header_map.find("sn")->second];
			user_list.back()->mail = row[header_map.find("mail")->second];
			for (auto proxy_address : Utils::split(row[header_map.find("mailLocalAddress")->second], ';')) {
				if( !proxy_address.empty() )
				user_list.back()->proxy_addresses.push_back(std::string(proxy_address));
			}

			for (auto safe_entry : Utils::split(row[header_map.find("safelist")->second], ';')) {
				user_list.back()->safe.push_back(std::string(safe_entry));
			}

			for (auto safe_entry : Utils::split(row[header_map.find("blocklist")->second], ';')) {
				if( !safe_entry.empty() )
					user_list.back()->block.push_back(std::string(safe_entry));
			}
			user_list.back()->safe_count = 0;
			user_list.back()->block_count = 0;
			count++;
		}
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << std::setw(25) << "User Load Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << user_file << std::endl;
}

void Proofpoint::UserSafeList::Save(const std::string& user_file)
{
	std::size_t count = 0;
	RE2 quoted("\"");
	const char delim{'"'};
	const char escape{'"'};

	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ios_base::sync_with_stdio(false);
	std::ofstream f(user_file);
	f  << "\"" << "givenName"
	  << "\",\"" << "sn"
	  << "\",\"" << "mail"
	  << "\",\"" << "mailLocalAddress"
	  << "\",\"" << "safelist"
	  << "\",\"" << "blocklist"
	  << "\",\"" << "safe_count"
	  << "\",\"" << "block_count" <<"\"\r\n";

	auto concat = [](const std::string& a, const std::string& b) -> std::string { return a + (a.size() > 0 ? ";" : "") + b;};

	for (const auto& user : user_list) {
		f << "\"" << user->fname
		  << "\",\"" << user->lname
		  << "\",\"" << user->mail
		  << "\",\"" << std::accumulate(user->proxy_addresses.begin(), user->proxy_addresses.end(), std::string(), concat )
		  << "\",\"" << std::accumulate(user->safe.begin(), user->safe.end(), std::string(), concat)
		  << "\",\"" << std::accumulate(user->block.begin(), user->block.end(), std::string(), concat)
		  << "\",\"" << user->safe_count
		  << "\",\"" << user->block_count << "\"\r\n";
		count++;
	}

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::ios_base::sync_with_stdio(true);
	std::cout << std::left << std::setw(25) << "SL Save Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << user_file << std::endl;
}
/*
inline Proofpoint::UserSafeList::FieldType Proofpoint::UserSafeList::GetFieldType(const std::string& field)
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

inline const std::string& Proofpoint::UserSafeList::GetFieldTypeString(Proofpoint::UserSafeList::FieldType field)
{
	return FieldTypeStrings[static_cast<int>(field)];
}

inline Proofpoint::UserSafeList::MatchType Proofpoint::UserSafeList::GetMatchType(const std::string& field)
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

inline const std::string& Proofpoint::UserSafeList::GetMatchTypeString(Proofpoint::UserSafeList::MatchType matchtype)
{
	return MatchTypeStrings[static_cast<int>(matchtype)];
}
 	 */
