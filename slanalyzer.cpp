/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "src/GlobalAnalyzer.h"
#include "src/UserAnalyzer.h"
#include "src/Matcher.h"
#include <getopt.h>
#include <filesystem>
#include <chrono>
#include <iostream>
#include "src/UserList.h"

using namespace std;
using namespace std::chrono;

void help()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST ] [-u USEREXPORT ] [-o OUTPUTFILE] [SMART_SEARCH_FILES...]"
		 << endl
		 << endl
		 << "Search multiple smart search exports to determine which safe or block list entries triggered against the mail flow."
		 << endl
		 << endl
		 << "Report Type Options (choose one):"
		 << endl
		 << "-s, --safelist        Exported Proofpoint organizational safe / block list CSV to use for analysis"
		 << endl
		 << "-u, --userlist        Exported Proofpoint user CSV export for personal safe / blocked list used for analysis"
		 << endl
		 << endl
		 << "Output Options:"
		 << endl
		 << "-o, --output          (required) Output report based on report type chosen"
		 << endl
		 << "-x, --extended        (optional) Only applies to user list exports provides full details of block and safe lists and field that matched"
		 << endl
		 << "-h, --help            show this help message and exit"
		 << endl
		 << endl
		 << "Positional Arguments:"
		 << endl
		 << "SS_FILES              (required positional) one or more cloud smart search exports."
		 << endl
		 << endl;
}

void usage()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST ] [-u USEREXPORT ] [-o OUTPUTFILE] [SMART_SEARCH_FILES...]" << endl
		 << "Try 'slanalyzer --help' for more information." << endl;
}
int main(int argc, char* argv[])
{
	if (argc==1) {
		usage();
		exit(1);
	}

	int c;
	string safe_list;
	string user_list;
	string output_list;
	vector<string> ss_inputs;
	bool safe = false;
	bool user = false;
	bool extended = false;
	bool output = false;
	bool files = false;

	static struct option long_options[] =
			{
					{("safelist"), required_argument, 0, 's'},
					{("userlist"), required_argument, 0, 'u'},
					{("extended"), required_argument, 0, 'x'},
					{("output"), required_argument, 0, 'o'},
					{("help"), no_argument, 0, 'h'},
					{0, 0, 0, 0}
			};

	int option_index = 0;

	while ((c = getopt_long(argc, argv, "s:u:xo:h", long_options, &option_index))!=-1) {
		switch (c) {
		case 's': safe_list = optarg;
			safe = true;
			break;
		case 'u': user_list = optarg;
			user = true;
			break;
		case 'x':
			extended = true;
			break;
		case 'o': output_list = optarg;
			output = true;
			break;
		case 'h': help();
			exit(0);
			break;
		case '?':
		default: usage();
			exit(1);
			break;
		}
	}

	if (optind<argc) {
		files = true;
		while (optind<argc) {
			if (!filesystem::exists(argv[optind])) {
				cerr << "Smart search file " << quoted(argv[optind]) << " doesn't exist." << endl;
				exit(1);
			}
			ss_inputs.emplace_back(argv[optind]);
			optind++;
		}
	}

	if( safe && user ){
		cerr << "Argument --safelist and --userlist can not be combined." << endl;
		exit(1);
	}

	if (safe && safe_list.empty()) {
		cerr << "Input list can not be an empty string." << endl;
		exit(1);
	}

	if (safe && !filesystem::exists(safe_list)) {
		cerr << "Input list: " << quoted(safe_list) << " doesn't exist" << endl;
		exit(1);
	}

	if (user && user_list.empty()) {
		cerr << "User list can not be an empty string." << endl;
		exit(1);
	}

	if (user && !filesystem::exists(user_list)) {
		cerr << "User list: " << quoted(user_list) << " doesn't exist" << endl;
		exit(1);
	}

	if (output && output_list.empty()) {
		cerr << "Output file can not be an empty string." << endl;
		exit(1);
	}

	filesystem::path p(output_list);
	if (filesystem::is_directory(p)) {
		cerr << "Output file is a directory: " << quoted(output_list)
			 << " please specify a filename" << endl;
		exit(1);
	}

	if (ss_inputs.empty()) {
		cerr << "Smart search files must be provided." << endl;
		exit(1);
	}

	if (!(safe || user) || !output || !files) {
		usage();
		exit(1);
	}

	auto start = high_resolution_clock::now();
	if( safe ) {

		Proofpoint::GlobalList safelist;
		Proofpoint::GlobalList::EntryErrors entry_errors;

		auto s = high_resolution_clock::now();
		safelist.Load(safe_list, entry_errors);
		auto e = high_resolution_clock::now();
		auto d = duration_cast<microseconds>(e-s);

		std::cout << std::left << "### Global List Load Completed ###" << std::endl
				  << std::right << std::setw(25) <<  "Load Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
				  << std::right << std::setw(25) << "List Count: "
				  << std::left << std::setw(25) << safelist.GetCount() << std::endl
				  << std::right << std::setw(25) << "List Errors: "
				  << std::left << std::setw(25) << entry_errors.size() << std::endl
				  << std::right << std::setw(25) << "List File: "
				  << safe_list << std::endl << std::endl;


		// Used to collect pattern errors in the even there is a bad pattern
		Proofpoint::PatternErrors<std::size_t> pattern_errors;
		Proofpoint::GlobalAnalyzer processor;


		s = high_resolution_clock::now();
		processor.Load(safelist,pattern_errors);
		e = high_resolution_clock::now();
		d = duration_cast<microseconds>(e-s);
		std::cout << std::left << "### Preprocessing Completed ###" << std::endl
				  << std::right << std::setw(25) <<  "Load Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
				  << std::right << std::setw(25) << "Pattern Errors: "
				  << std::left << std::setw(25) << pattern_errors.size() << std::endl
				  << std::endl;

		std::size_t total_records_processed = 0;
		for (const auto& file : ss_inputs) {
			s = high_resolution_clock::now();
			std::size_t records_processed = 0;
			std::size_t header_index = processor.Process(file, safelist, records_processed);
			e = high_resolution_clock::now();
			d = duration_cast<microseconds>(e-s);
			total_records_processed += records_processed;
			std::cout << std::left << "### Analysis Completed ###" << std::endl
					  << std::right << std::setw(25) <<  "Analysis Time: "
					  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
					  << std::right << std::setw(25) << "Smart Search File: "
					  << file << ((header_index == -1) ? " (No CSV Header Found)" : "") << std::endl << std::endl;
		}
		std::cout << std::left << "### Analysis Summary ###" << std::endl
				  << std::right << std::setw(25) <<  "Total Inbound: "
				  << std::left << safelist.GetInboundCount() << std::endl
				  << std::right << std::setw(25) <<  "Total Outbound: "
				  << std::left << safelist.GetOutboundCount() << std::endl << std::endl;

		s = high_resolution_clock::now();
		safelist.Save(output_list);
		e = high_resolution_clock::now();
		d = duration_cast<microseconds>(e-s);
		std::ios_base::sync_with_stdio(true);
		std::cout << std::left << "### Global List Save Completed ###" << std::endl
				  << std::right << std::setw(25) <<  "Save Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl << std::endl;

		if (!pattern_errors.empty()) {
			cerr << endl << endl << endl << "Pattern errors occurred, see the following entries in your safe or blocked list:" << endl;
			for (auto e : pattern_errors) {
				cerr << "Line: " << e.index << " Pattern: " << e.pattern << " Reason: " << e.error << endl;
			}
			cerr << std::endl;
		}

		if (!entry_errors.empty()) {
			cerr << endl << endl << endl << "Entry errors occurred, see the following entries in your safe or blocked list:" << endl;
			for (auto e : entry_errors) {
				cerr << "Line: " << e.line << " FieldType: " << e.field_data << " MatchType: " << e.match_data << "Error: " << e.error << endl;
			}
		}
	}
	if( user ) {
		Proofpoint::UserList user_safe_list;
		Proofpoint::UserList::UserErrors user_errors;

		auto s = high_resolution_clock::now();
		user_safe_list.Load(user_list, user_errors);
		auto e = high_resolution_clock::now();
		auto d = duration_cast<microseconds>(e-s);

		std::cout << std::left << "### Users Load Completed ###" << std::endl
				  << std::right << std::setw(25) << "Load Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
				  << std::right << std::setw(25) << "User Count: "
				  << std::left << std::setw(25) << user_safe_list.GetUserCount() << std::endl
				  << std::right << std::setw(25) << "Address Count: "
				  << std::left << std::setw(25) << user_safe_list.GetUserAddressCount() << std::endl
				  << std::right << std::setw(25) << "Safe Count: "
				  << std::left << std::setw(25) << user_safe_list.GetSafeListCount() << std::endl
				  << std::right << std::setw(25) << "Block Count: "
				  << std::left << std::setw(25) << user_safe_list.GetBlockListCount() << std::endl
				  << std::right << std::setw(25) << "List File: "
				  << user_list << std::endl << std::endl;

		// Used to collect pattern errors in the even there is a bad pattern
		Proofpoint::PatternErrors<Proofpoint::UserAnalyzer::UserMatch> pattern_errors;

		Proofpoint::UserAnalyzer processor;

		s = high_resolution_clock::now();
		processor.Load(user_safe_list,pattern_errors);
		e = high_resolution_clock::now();
		d = duration_cast<microseconds>(e-s);
		std::cout << std::left << "### Preprocessing Completed ###" << std::endl
				  << std::right << std::setw(25) <<  "Load Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
				  << std::right << std::setw(25) << "Pattern Errors: "
				  << std::left << std::setw(25) << pattern_errors.size() << std::endl << std::endl;


		std::size_t total_records_processed = 0;
		for (const auto& file : ss_inputs) {
			s = high_resolution_clock::now();
			std::size_t records_processed = 0;
			std::size_t header_index = processor.Process(file, user_safe_list, records_processed);
			e = high_resolution_clock::now();
			d = duration_cast<microseconds>(e-s);
			total_records_processed += records_processed;
			std::cout << std::left << "### Analysis Completed ###" << std::endl
					  << std::right << std::setw(25) <<  "Analysis Time: "
					  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl
					  << std::right << std::setw(25) << "Smart Search File: "
					  << file << ((header_index == -1) ? " (No CSV Header Found)" : "") << std::endl << std::endl;
		}
		std::cout << std::left << "### Analysis Summary ###" << std::endl
		          << std::right << std::setw(25) <<  "Total Safe Listed: "
				  << std::left << user_safe_list.GetSafeCount() << std::endl
				  << std::right << std::setw(25) <<  "Total Block Listed: "
				  << std::left << user_safe_list.GetBlockCount() << std::endl << std::endl;

		s = high_resolution_clock::now();
		user_safe_list.Save(output_list, extended);
		e = high_resolution_clock::now();
		d = duration_cast<microseconds>(e-s);
		std::ios_base::sync_with_stdio(true);
		std::cout << std::left << "### Users Save Completed ###" << std::endl
		          << std::right << std::setw(25) <<  "Save Time: "
				  << std::left << std::setprecision(9) << (double)d.count()/1000000 << "s" << std::endl << std::endl;
	}

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	std::cout << std::left << "### Processing Completed ###" << std::endl
	          << std::right << std::setw(25) <<  "Total Processing Time: "
			  << std::left << std::setprecision(9) << (double)duration.count()/1000000 << "s" << std::endl << std::endl;

	return 0;
}
