#!/usr/bin/perl

use strict;
use Getopt::Long;

my(@defined, @undefined, $norecurse, $help);
&GetOptions ("defined=s@" => \@defined,
             "undefined=s@" => \@undefined,
             "norecurse" => \$norecurse,
             "help" => \$help,
             );


my(@paths) = @ARGV;
my($retval) = 0;
if ($help || !scalar(@paths))
{
   usage();
   exit;
}

# Check to make sure unifdef is in path
unless(`which ./unifdef`)
{
   die "ERROR: the program 'unifdef' must be in your path.  It is avialable at octsw/utils\n";
}

# create egrep expression to find all matching files

my($macro);
my($egrep_arg) = 'CAVIUM_ONLY';
foreach $macro (@defined, @undefined)
{
   unless ($macro =~ /^CAVIUM_ONLY/)
   {
      $egrep_arg = $egrep_arg.'|'.$macro;

   }
}
my($find_depth) = '';
if ($norecurse)
{
   $find_depth = "-maxdepth 1";
}

my($find_cmd) = "find @paths $find_depth -type f";
#print "find command: $cmd\n";
my(@files) = `$find_cmd`;
chomp(@files);

# Limit this to specified file names *.[ch], Makefile, etc

@files = grep{/\.[ch]$/ || /Makefile$/} @files;


# We now have a list of all files that we need  to process, so
# process each one in turn.
unless (scalar(@files))
{
   print "No matching files found\n";
}
my($file);
foreach $file (@files)
{
   process_file($file, \@defined, \@undefined);
}

exit($retval);


#####################################################################
sub usage
{
   print "Usage: process-ifdefs.pl [--defined <DEFINED_MACRO>] [--undefined <UNDEFINED_MACRO>] [-norecurse] <path> [<path]\n";
   print "Multiple --undefined and --defined options may be used to specify multiple macros to be defined or undefined.\n";
   print "By default all macros of the form CAVIUM_ONLY* are undefined, use the -D to override.\n";
   print "Only *.c *.h and Makefile files are processed.\n";
   print "The provided paths are processed recursively unless the -norecurse option is used\n";
   print "Option names may be shortened to the shortest unique string.\n";
   
}
#####################################################################
sub process_file($@@)
{
   my($file, $defined_ref, $undefined_ref) = @_;
   my(@defined) = @$defined_ref;
   my(@undefined) = @$undefined_ref;

   print "Processing file: $file\n";

   # Now we need to get actual list of CAVIUM_ONLY based macros on file
   # We want to handle any CAVIUM_ONLY* macro name that may be in a file
   # All CAVIUM_ONLY macros are undefined by default, unless overidden on
   # the command line.

   my(@lines);    
   open( FH, $file ) or die "unable to open (READ) file: $file\n";
   @lines = <FH>;
   close(FH);
   @lines = grep(/CAVIUM_ONLY/,@lines);
   my(%co_macros); # use hash to remove duplicates
   foreach (@lines)
   {
      if (/(CAVIUM_ONLY\w*)/)
      {
         $co_macros{$1} = $1;
      }
   }
   my(@co_macros) = keys(%co_macros);

#   print "CAVIUM_ONLY macros found in file $file: @co_macros \n";

   # Compose argument list to unifdef to define/undefine the appropriate macros

   # remove any CAVIUM_ONLY macros that should be defined from co list, add rest
   # to undefined list
   my($macro);
   foreach $macro (@co_macros)
   {
      unless (ismember($macro,@defined))
      {
         push(@undefined, $macro)
      }
   }

   my($unifdef_args);
   foreach $macro (@defined)
   {
      $unifdef_args .= " -D$macro";
   }
   foreach $macro (@undefined)
   {
      $unifdef_args .= " -U$macro";
   }
#   print "Unifdef args: $unifdef_args\n";

   my(@unifdef_output) = `./unifdef -p $unifdef_args $file`;
   my $err = $? >> 8;
   # 0 is no change, 1 is OK, 2 is error
   if ($err != 1 && $err != 2)
   {
      if ($err != 0) {
         warn "ERROR: unifdef returned error for file: $file\n";
         $retval = -1;
      }
   }
   else
   {
      open( FH, ">$file" ) or die "unable to open (WRITE) file: $file\n";
      print FH @unifdef_output;
      close(FH);
   }

}


#####################################################################
sub ismember($@)
{
   my($mem, @list) = @_;
   foreach (@list)
   {
      if ($mem eq $_)
      {
         return(1);
      }
   }
   return(0);
}
