#!/usr/bin/perl
#
# Copyright (c) 1999-2004 Andre Oppermann,
#      Internet Business Solutions AG, CH-8005 Zürich, Switzerland
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#      This product includes software developed by Internet Business
#      Solutions AG and its contributors.
# 4. Neither the name of the author nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

# $localhost and $server need to changed
# If a file by the name "done" exists in the maildir we don't try to
# fetch the mails again.
# by Ingo Oppermann

use Mail::POP3Client;

# Variables

$path       = $ARGV[3];
$mailpath   = "./".$path;
$username   = $ARGV[0];
$pw         = $ARGV[1];
$server     = 'mail.pipeline.ch';
$localhost  = "mail.schweizerinserate.ch";
@filenames;

# Main

if(-e $mailpath."/done")
{
        ;
}
else
{
        $pop = new Mail::POP3Client($username,$pw,$server);
        $numofmails = $pop->Count;
        print $numofmails;
        for($i = 1; $i <= $numofmails; $i++)
        {
                $curtime = time();
                $random = rand();
                $filename = $curtime.".".$$.".".$random.$localhost;
                push(@filenames, $filename);
                open(OUT, ">".$mailpath."/tmp/".$filename);
                foreach($pop->Retrieve($i))
                {
                        print OUT $_, "\n";
                }
# Uncomment the next line if the retrieved mail should be deleted from
# the old pop server
        #       $pop->Delete($i);
                close(OUT);
        }
        $pop->Close;

        foreach(@filenames)
        {
                $filename = $_;
                $program = "mv $mailpath/tmp/$filename $mailpath/new/$filename";
                open(PROG, "|$program");
                close(PROG);
        }
        open(CHECK, ">$mailpath/done");
        print CHECK 1;
        close(CHECK);
}

exec "$ARGV[2] $ARGV[3]";

