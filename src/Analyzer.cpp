/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "Analyzer.h"
#include "CsvParser.h"
#include <chrono>
#include <iostream>
#include <iomanip>
#include "re2/re2.h"
#include "Utils.h"

Proofpoint::Analyzer::Analyzer(const SafeList& safelist, PatternErrors& pattern_errors)
{
	for (std::size_t i = 0; i<safelist.safe_list.size(); i++) {
		std::shared_ptr<SafeList::Entry> sle = safelist.safe_list.at(i);
		switch (sle->field_type) {
		case FieldType::IP: ip.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::HOST: host.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::HELO: helo.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::FROM: from.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::HFROM: hfrom.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::RCPT: rcpt.Add(sle->match_type, sle->pattern, i, pattern_errors);
			break;
		case FieldType::UNKNOWN: break;
		}
	}
}
void Proofpoint::Analyzer::Process(const std::string& ss_file, SafeList& safelist)
{
	std::size_t count = 0;
	bool header_found;
	using std::chrono::high_resolution_clock;
	using std::chrono::microseconds;
	auto start = high_resolution_clock::now();
	std::ifstream f(ss_file);
	csv::CsvParser parser(f);
	re2::StringPiece matches[2];
	RE2 hfrom_addr_only(R"(<?\s*([a-zA-Z0-9.!#$%&’*+\/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)\s*>?\s*(?:;|$))");
	RE2 inbound_check(R"(\bdefault_inbound\b)");

	csv::HeaderMap header_map;
	csv::HeaderList required_headers{"Policy_Route",
			"Sender_IP_Address",
			"Sender_Host",
			"HELO",
			"Header_From",
			"Sender",
			"Recipients"};

	// Validate there are headers we are interested in...
	header_found = parser.FindHeader(required_headers, header_map);

	// std::multimap is useful for CSVs where there may be duplicate headers.
	//for (auto i = header_map.begin(); i!= header_map.end(); i++){
	//	std::cout << std::setw(35) << i->first << " " << std::setw(25) << i->second  << " " << header_map.count(i->first) << "\r\n";
	//}

	for (auto& row : parser){
		bool inbound = RE2::PartialMatch(row[header_map.find("Policy_Route")->second], inbound_check);
		ip.Match(inbound, row[header_map.find("Sender_IP_Address")->second], safelist.safe_list);
		host.Match(inbound, row[header_map.find("Sender_Host")->second], safelist.safe_list);
		helo.Match(inbound, row[header_map.find("HELO")->second], safelist.safe_list);
		// This single call has large impact on processing. Since we need to perform header from "address only"
		hfrom.Match(inbound, (hfrom_addr_only.Match(row[header_map.find("Header_From")->second], 0,
				row[header_map.find("Header_From")->second].length(), RE2::UNANCHORED, matches, 2))
				? matches[1].ToString() : row[header_map.find("Header_From")->second], safelist.safe_list);
		from.Match(inbound, row[header_map.find("Sender")->second], safelist.safe_list);
		rcpt.Match(inbound, row[header_map.find("Recipients")->second], safelist.safe_list);
		count++;
	}

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << std::setw(25) << "SS Processing Completed" << " "
			  << std::left << std::setw(25) << std::to_string(duration.count()) << " "
			  << std::setw(25) << std::setprecision(2) << std::to_string((double)duration.count()/1000000) << " "
			  << std::setw(25) << count << " "
			  << ss_file << ((!header_found) ? " (No CSV Header Found)" : " ") << std::endl;
}
