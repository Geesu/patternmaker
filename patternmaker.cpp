/*
 *  Pattern Maker
 *
 *      Want to create patterns?  This plugin will do it!
 *
 */

#ifdef NO_OBSOLETE_FUNCS
#undef NO_OBSOLETE_FUNCS
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include <ua.hpp>

#include <stdio.h>

//--------------------------------------------------------------------------
int idaapi init(void)
{
	if ( get_entry_qty() == 0 )
		return PLUGIN_SKIP;
	return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void idaapi run(int /*arg*/)
{
	if ( !autoIsOk() ){
		msg( "Please wait until analysis is complete!\n" );
		return;
	}

	// something is selected!
	ea_t start, end;
	if ( read_selection( &start, &end ) ){

		char funcname[128];// = NULL;
		if ( get_func_name(start, funcname, 128) == NULL ){
			funcname[0] = '\0';
		}

		//int i = start;
		func_item_iterator_t fii;
		bool ok = fii.set_range(start, end);

		ea_t line = fii.current();

		// generate our mask
		char mask[256] = {0};
		init_output_buffer(mask, sizeof(mask));
		while ( ok ){

			// do we have an xref in this line?
			ea_t xref = get_first_dref_from(line);
			ea_t endLineAddress = get_item_end(line);
			if ( xref == -1 ){
				xref = get_first_fcref_from(line);
			}

			// TODO: Find a method to locate how long the XREF is, and where it begins

			// xref found!
			int numInstructions = endLineAddress - line;
			if ( xref != -1 ){
	
				// I can about guarantee this is stupid, but I don't know a better method
				if ( numInstructions == 2 ){	
					out_snprintf("x?");
				}
				else if ( numInstructions == 5 ){
					out_snprintf("x????");
				}
				else if ( numInstructions == 6 ){
					out_snprintf("xx????");
				}
				else{
					for(int x = 0; x < numInstructions; x++ ){
						out_snprintf("x");
					}
				}
			}
			else{
				for(int x = 0; x < numInstructions; x++ ){
					out_snprintf("x");
				}
			}

			ok = fii.next_not_tail();
			line = fii.current();
		}
		term_output_buffer();

		func_item_iterator_t fi;
		ok = fi.set_range(start, end);
		line = fi.current();

		// generate the pattern
		char pattern[1024] = {0};
		init_output_buffer(pattern, sizeof(pattern));
		while ( ok ){

			ea_t endLineAddress = get_item_end(line);

			for ( int x = line; x < endLineAddress; x++ ){
				out_snprintf("/x%02X", get_byte(x));
			}

			ok = fi.next_not_tail();
			line = fi.current();
		}
		term_output_buffer();

		static const char form[] = "STARTITEM 0\n"
		"Pattern below!\n\n"
		"\n"
		"<~P~attern:A:4096:64::>\n"
		"<~M~ask:A:4096:64::>\n"
		"<~F~unction:A:256:64::>\n";

		char buf[MAXSTR];
		qstrncpy(buf, pattern, sizeof(buf));
		AskUsingForm_c(form, buf, &mask, &funcname);
	}

	return;	
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize
	NULL,
	run,                  // invoke plugin
	"Generates patterns for the selected disassembly",
	"Generates patterns for the selected disassembly",
	
	"Pattern Maker",
	"Ctrl-F12",
};
