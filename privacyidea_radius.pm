#
#    privacyIDEA FreeRADIUS plugin
#    2021-07-23 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               URL encode parameters
#    2020-09-09 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add Packet-Src-IP-Address as fallback for client IP.
#    2020-03-21 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add ADD_EMPTY_PASS to send an empty password to
#               privacyIDEA in case no password is given.
#               Allow config section to have different modules
#               with different config files.
#    2019-03-17 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add password splitting
#    2018-01-12 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Substrings of multivalue user attributes can be added
#               to the RADIUS response.
#    2017-10-16 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add Calling-Station-Id
#    2016-09-30 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add attribute mapping
#    2016-08-13 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add user-agent to be displayed in
#               privacyIDEA Client Applicaton Type
#    2015-10-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add privacyIDEA-Serial to the response.
#    2015-10-09 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Improve the reading of the config file.
#    2015-09-25 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add the possibility to read config from
#               /etc/privacyidea/rlm_perl.ini
#    2015-06-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               Add using of Stripped-User-Name and Realm from the
#               RAD_REQUEST
#    2015-04-10 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#               fix typo in log
#    2015-02-25 cornelius kölbel <cornelius@privacyidea.org>
#               remove the usage of simplecheck and use /validate/check
#    2014-06-25 Cornelius Kölbel
#               changed the used modules from Config::Files to Config::IniFile
#               to make it easily run on CentOS with EPEL, without CPAN
#
#    Copyright (C) 2010 - 2014 LSE Leading Security Experts GmbH
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    Copyright 2002  The FreeRADIUS server project
#    Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#    Copyright 2011  LSE Leading Security Experts GmbH
#
#    E-mail: linotp@lsexperts.de
#    Contact: www.linotp.org
#    Support: www.lsexperts.de




#
# Based on the Example code for use with rlm_perl
#
#

=head1 NAME

freeradius_perl - Perl module for use with FreeRADIUS rlm_perl, to authenticate against
  LinOTP      http://www.linotp.org
  privacyIDEA http://www.privacyidea.org

=head1 SYNOPSIS

   use with freeradius:

   Configure rlm_perl to work with privacyIDEA:
   in /etc/freeradius/users
    set:
     DEFAULT Auth-type := perl

  in /etc/freeradius/modules/perl
     point
     perl {
         module =
  to this file

  in /etc/freeradius/sites-enabled/<yoursite>
  set
  authenticate{
    perl
    [....]

=head1 DESCRIPTION

This module enables freeradius to authenticate using privacyIDEA or LinOTP.

   TODO:
     * checking of server certificate


=head2 Methods

   * authenticate


=head1 CONFIGURATION

The authentication request with its URL and default LinOTP/privacyIDEA Realm
could be defined in a dedicated configuration file, which is expected to be:

  /opt/privacyIDEA/rlm_perl.ini

This configuration file could contain default definition for URL and REALM like
  [Default]
  URL = http://192.168.56.1:5001/validate/check
  REALM =

But as well could contain "Access-Type" specific configurations, e.g. for the
Access-Type 'scope1', this would look like:

  [Default]
  URL = https://localhost/validate/check
  REALM =
  CLIENTATTRIBUTE = Calling-Station-Id

  [scope1]
  URL = http://192.168.56.1:5001/validate/check
  REALM = mydefault

=head1 AUTHOR

Cornelius Koelbel (cornelius.koelbel@lsexperts.de)
Cornelius Koelbel (conrelius@privacyidea.org)

=head1 COPYRIGHT

Copyright 2013, 2014

This library is free software; you can redistribute it
under the GPLv2.

=head1 SEE ALSO

perl(1).

=cut

use strict;
use LWP 6;
use Config::IniFiles;
use Data::Dump;
use Try::Tiny;
use JSON;
use Time::HiRes qw( gettimeofday tv_interval sleep );
use URI::Encode;
use Encode::Guess;


# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG %RAD_PERLCONF);

# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;


# constant definition for the remapping of return values
use constant RLM_MODULE_REJECT  =>  0; #  /* immediately reject the request */
use constant RLM_MODULE_FAIL    =>  1; #  /* module failed, don't reply */
use constant RLM_MODULE_OK      =>  2; #  /* the module is OK, continue */
use constant RLM_MODULE_HANDLED =>  3; #  /* the module handled the request, so stop. */
use constant RLM_MODULE_INVALID =>  4; #  /* the module considers the request invalid. */
use constant RLM_MODULE_USERLOCK => 5; #  /* reject the request (user is locked out) */
use constant RLM_MODULE_NOTFOUND => 6; #  /* user not found */
use constant RLM_MODULE_NOOP     => 7; #  /* module succeeded without doing anything */
use constant RLM_MODULE_UPDATED  => 8; #  /* OK (pairs modified) */
use constant RLM_MODULE_NUMCODES => 9; #  /* How many return codes there are */

our $ret_hash = {
    0 => "RLM_MODULE_REJECT",
    1 => "RLM_MODULE_FAIL",
    2 => "RLM_MODULE_OK",
    3 => "RLM_MODULE_HANDLED",
    4 => "RLM_MODULE_INVALID",
    5 => "RLM_MODULE_USERLOCK",
    6 => "RLM_MODULE_NOTFOUND",
    7 => "RLM_MODULE_NOOP",
    8 => "RLM_MODULE_UPDATED",
    9 => "RLM_MODULE_NUMCODES"
};

## constant definition for comparison
use constant false => 0;
use constant true  => 1;

## constant definitions for logging
use constant Debug => 1;
use constant Auth  => 2;
use constant Info  => 3;
use constant Error => 4;
use constant Proxy => 5;
use constant Acct  => 6;


# You can configure, which config file to use in the perl module definition:
# perl privacyIDEA-A {
#   filename = /usr/share/privacyidea/freeradius/privacyidea_radius.pm
#   config {
#        configfile = /etc/privacyidea/rlm_perl-A.ini
#        }
# }
our $CONFIG_FILE = $RAD_PERLCONF{'configfile'};
our @CONFIG_FILES = ("/etc/privacyidea/rlm_perl.ini", "/etc/freeradius/rlm_perl.ini", "/opt/privacyIDEA/rlm_perl.ini");


our $Config = {};
our $Mapping = {};
our $cfg_file;

$Config->{FSTAT} = "not found!";
$Config->{URL}     = 'https://127.0.0.1/validate/check';
$Config->{REALM}   = '';
$Config->{CLIENTATTRIBUTE} = '';
$Config->{RESCONF} = "";
$Config->{Debug}   = "FALSE";
$Config->{SSL_CHECK} = "FALSE";
$Config->{TIMEOUT} = 10;
$Config->{SPLIT_NULL_BYTE} = "FALSE";
$Config->{ADD_EMPTY_PASS} = "FALSE";
# Server-side polling for push tokens via /validate/polltransaction.
# When POLL is enabled and privacyIDEA returns a "poll" client_mode challenge
# (i.e. a push token), the module polls privacyIDEA for confirmation instead of
# returning an Access-Challenge with an (empty) input field to the RADIUS client.
# This frees the scarce privacyIDEA (Apache/wsgi) workers that the push_wait
# policy would otherwise hold open; a FreeRADIUS worker is still held for the
# wait (as it was under push_wait). See poll_push.
$Config->{POLL} = "FALSE";
$Config->{POLL_TIMEOUT} = 60;
$Config->{POLL_INTERVAL} = 3;

if ($CONFIG_FILE) {
    @CONFIG_FILES = ($CONFIG_FILE);
}

foreach my $file (@CONFIG_FILES) {
    if (( -e $file )) {
        $cfg_file = Config::IniFiles->new( -file => $file);
        $CONFIG_FILE = $file;
        $Config->{FSTAT} = "found!";
        $Config->{URL} = $cfg_file->val("Default", "URL");
        $Config->{REALM}   = $cfg_file->val("Default", "REALM");
        $Config->{RESCONF} = $cfg_file->val("Default", "RESCONF");
        $Config->{Debug}   = $cfg_file->val("Default", "DEBUG");
        $Config->{SPLIT_NULL_BYTE} = $cfg_file->val("Default", "SPLIT_NULL_BYTE");
        $Config->{ADD_EMPTY_PASS} = $cfg_file->val("Default", "ADD_EMPTY_PASS");
        $Config->{SSL_CHECK} = $cfg_file->val("Default", "SSL_CHECK");
        $Config->{SSL_CA_PATH} = $cfg_file->val("Default", "SSL_CA_PATH");
        $Config->{TIMEOUT} = $cfg_file->val("Default", "TIMEOUT", 10);
        $Config->{CLIENTATTRIBUTE} = $cfg_file->val("Default", "CLIENTATTRIBUTE");
        $Config->{POLL} = $cfg_file->val("Default", "POLL", "FALSE");
        $Config->{POLL_TIMEOUT} = $cfg_file->val("Default", "POLL_TIMEOUT", 60);
        $Config->{POLL_INTERVAL} = $cfg_file->val("Default", "POLL_INTERVAL", 3);
    }
}

sub add_reply_attibute {

    my $radReply = shift;
    my $newValue = shift;

    if (ref($radReply) eq "ARRAY") {
        # This is an array, there is already a value to this replyAttribute
        #&radiusd::radlog( Info, "Adding $newValue to the Reply Attribute, being an array.\n");
        push @$radReply, $newValue;
    } else {
        # This is an empty replyValue, we add the first value
        #&radiusd::radlog( Info, "Adding $newValue to the Reply Attribute, being a string.\n");
        $radReply = [$newValue];
    }
    return $radReply;
}

sub mapResponse {
    # This function maps the Mapping sections in rlm_perl.ini
    # to RADIUS Attributes.
    my $decoded = shift;
    my %radReply;
    my $topnode;
    if ($cfg_file) {
        foreach my $group ($cfg_file->Groups) {
            &radiusd::radlog( Info, "++++ Parsing group: $group\n");
            foreach my $member ($cfg_file->GroupMembers($group)) {
                &radiusd::radlog(Info, "+++++ Found member '$member'");
                $member =~/(.*)\ (.*)/;
                $topnode = $2;
                if ($group eq "Mapping") {
                    foreach my $key ($cfg_file->Parameters($member)){
                        my $radiusAttribute = $cfg_file->val($member, $key);
                        &radiusd::radlog( Info, "++++++ Map: $topnode : $key -> $radiusAttribute");
                        my $newValue = $decoded->{detail}{$topnode}{$key};
                        $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, $newValue);
                    };
                }
                if ($group eq "Attribute") {
                    my $radiusAttribute = $topnode;
                    # opional overwrite radiusAttribute
                    my $ra = $cfg_file->val($member, "radiusAttribute");
                    if ($ra ne "") {
                        $radiusAttribute = $ra;
                    }
                    my $userAttribute = $cfg_file->val($member, "userAttribute");
                    my $regex = $cfg_file->val($member, "regex");
                    my $directory = $cfg_file->val($member, "dir");
                    my $prefix = $cfg_file->val($member, "prefix");
                    my $suffix = $cfg_file->val($member, "suffix");
                    &radiusd::radlog( Info, "++++++ Attribute: IF '$directory'->'$userAttribute' == '$regex' THEN '$radiusAttribute'");
                    my $attributevalue="";
                    if ($directory eq "") {
                        $attributevalue = $decoded->{detail}{$userAttribute};
                        &radiusd::radlog( Info, "++++++ no directory");
                    } else {
                        $attributevalue = $decoded->{detail}{$directory}{$userAttribute};
                        &radiusd::radlog( Info, "++++++ searching in directory $directory");
                    }
                    my @values = ();
                    if (ref($attributevalue) eq "") {
                        &radiusd::radlog(Info, "+++++++ User attribute is a string: $attributevalue");
                        push(@values, $attributevalue);
                    }
                    if (ref($attributevalue) eq "ARRAY") {
                        &radiusd::radlog(Info, "+++++++ User attribute is a list: $attributevalue");
                        @values = @$attributevalue;
                    }
                    foreach my $value (@values) {
                        &radiusd::radlog(Info, "+++++++ trying to match $value");
                        if ($value =~ /$regex/) {
                            my $result = $1;
                            $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, "$prefix$result$suffix");
                            &radiusd::radlog(Info, "++++++++ Result: Add RADIUS attribute $radiusAttribute = $prefix$result$suffix");
                        } else {
                            &radiusd::radlog(Info, "++++++++ Result: No match, no RADIUS attribute $radiusAttribute added.");
                        }
                    }
                }
            }
        }

        foreach my $key ($cfg_file->Parameters("Mapping")) {
            my $radiusAttribute = $cfg_file->val("Mapping", $key);
            &radiusd::radlog( Info, "+++ Map: $key -> $radiusAttribute");
            $radReply{$radiusAttribute} = add_reply_attibute($radReply{$radiusAttribute}, $decoded->{detail}{$key});
        }
    }
    return %radReply;
}

sub poll_url {
    # Derive the /validate/polltransaction endpoint from the configured
    # /validate/check URL. Tolerates a trailing slash and proxied path prefixes
    # (e.g. https://host/pi/validate/check/). Returns the URL unchanged if it
    # does not contain a /validate/check suffix (caller should warn).
    my $url = shift;
    ( my $poll = $url ) =~ s{/validate/check/?$}{/validate/polltransaction};
    return $poll;
}

sub poll_push {
    # Server-side polling for push confirmation via /validate/polltransaction.
    #
    # This is used instead of returning an Access-Challenge for "poll" type push
    # tokens, so the RADIUS client does not prompt the user for input the user
    # cannot provide. The privacyIDEA server is NOT blocked (we poll instead of
    # relying on the server-side push_wait), but this DOES block the FreeRADIUS
    # worker thread for up to $timeout seconds - the accepted trade-off on
    # FreeRADIUS 3. Make sure the NAS request timeout is raised accordingly and
    # that the thread pool is sized for the expected number of concurrent pushes.
    my ( $ua, $url, $params, $decoded, $timeout, $interval ) = @_;
    my $transaction_id = $decoded->{detail}{transaction_id};

    # Guard against blank / non-numeric config values (e.g. POLL_TIMEOUT="").
    $timeout  = 60 if ( !defined($timeout)  || $timeout  !~ /^\d*\.?\d+$/ || $timeout  <= 0 );
    $interval = 3  if ( !defined($interval) || $interval !~ /^\d*\.?\d+$/ || $interval <= 0 );

    my $poll_url = poll_url( $url );
    if ( $poll_url eq $url ) {
        &radiusd::radlog( Error, "Could not derive polltransaction URL from '$url' (expected a /validate/check suffix); polling may target the wrong endpoint" );
    }

    my $coder = JSON->new->ascii->pretty->allow_nonref;
    # transaction_id goes into a GET query string, so URL-encode it.
    my $uri = URI::Encode->new( { encode_reserved => 1 } );
    my $tx_enc = $uri->encode( $transaction_id );

    # Budget on wall-clock time (includes HTTP time), not just accumulated sleeps,
    # so the worker is never held much longer than $timeout.
    my $start = [gettimeofday];
    &radiusd::radlog( Info, "Push token: polling transaction $transaction_id for up to $timeout seconds" );

    while ( tv_interval($start) < $timeout ) {
        my $resp = $ua->get( "$poll_url?transaction_id=$tx_enc" );
        if ( $resp->is_success ) {
            my $pdec = eval { $coder->decode( $resp->decoded_content ) };
            if ( $pdec ) {
                my $cstatus = $pdec->{detail}{challenge_status} || "";
                if ( $pdec->{result}{value} ) {
                    # Confirmed on the phone -> finalize with an empty-pass check.
                    &radiusd::radlog( Info, "Push confirmed (status='$cstatus'), finalizing $transaction_id" );
                    return finalize_transaction( $ua, $url, $params, $transaction_id );
                } elsif ( $cstatus eq "declined" ) {
                    # User declined on the phone -> reject, no point in polling on.
                    &radiusd::radlog( Info, "Push declined for $transaction_id" );
                    $RAD_REPLY{'Reply-Message'} = "privacyIDEA push declined";
                    return RLM_MODULE_REJECT;
                }
                # challenge_status "pending" (or unknown) -> keep polling.
            } else {
                &radiusd::radlog( Info, "Could not parse polltransaction response" );
            }
        } else {
            &radiusd::radlog( Info, "polltransaction request failed: ". $resp->status_line );
        }
        # Don't sleep if another interval would blow the budget (no trailing wait).
        last if ( tv_interval($start) + $interval >= $timeout );
        sleep( $interval );
    }

    # Timed out. Fall back to an Access-Challenge so the transaction can still be
    # completed on a subsequent request (e.g. a client that re-submits). Include
    # the mapped reply attributes, matching the normal challenge path.
    &radiusd::radlog( Info, "Push not confirmed within $timeout seconds, issuing challenge" );
    $RAD_REPLY{'State'} = $transaction_id;
    $RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
    %RAD_REPLY = ( %RAD_REPLY, mapResponse($decoded) );
    return RLM_MODULE_HANDLED;
}

sub finalize_transaction {
    # Complete a confirmed push by sending an empty-pass /validate/check with the
    # transaction_id. privacyIDEA replies with result->value true on success.
    my ( $ua, $url, $params, $transaction_id ) = @_;

    my $coder = JSON->new->ascii->pretty->allow_nonref;
    # Reuse the original request params (user, realm, resConf, client, ...) so the
    # transaction resolves in the same realm; just send an empty pass plus the
    # transaction_id to complete the challenge.
    my %fin = %{$params};
    $fin{pass}           = "";
    $fin{transaction_id} = $transaction_id;
    delete $fin{state};

    my $resp = $ua->post( $url, \%fin );
    if ( !$resp->is_success ) {
        # Transient/transport error after a confirmed push: soft-fail (like the
        # main flow) rather than hard-denying an already-confirmed user.
        my $status = $resp->status_line;
        &radiusd::radlog( Info, "privacyIDEA push finalize failed: $status" );
        $RAD_REPLY{'Reply-Message'} = "privacyIDEA request failed: $status";
        return RLM_MODULE_FAIL;
    }
    my $fdec = eval { $coder->decode( $resp->decoded_content ) };
    if ( !$fdec ) {
        &radiusd::radlog( Info, "Could not parse push finalize response" );
        $RAD_REPLY{'Reply-Message'} = "Can not parse response from privacyIDEA.";
        return RLM_MODULE_FAIL;
    }
    if ( $fdec->{result}{value} ) {
        &radiusd::radlog( Info, "privacyIDEA access granted (push) for $params->{user}" );
        $RAD_REPLY{'Reply-Message'} = "privacyIDEA access granted";
        %RAD_REPLY = ( %RAD_REPLY, mapResponse($fdec) );
        return RLM_MODULE_OK;
    }

    &radiusd::radlog( Info, "privacyIDEA denied access on push finalize for $params->{user}" );
    $RAD_REPLY{'Reply-Message'} = "privacyIDEA access denied";
    return RLM_MODULE_REJECT;
}

# Function to handle authenticate
sub authenticate {

    ## show where the config comes from -
    # in the module init we can't print this out, so it starts here
    &radiusd::radlog( Info, "Config File $CONFIG_FILE ".$Config->{FSTAT} );

    # we inherrit the defaults
    my $URL             = $Config->{URL};
    my $REALM           = $Config->{REALM};
    my $RESCONF         = $Config->{RESCONF};
    my $DEBUG           = $Config->{DEBUG};
    my $SPLIT_NULL_BYTE = $Config->{SPLIT_NULL_BYTE};
    my $ADD_EMPTY_PASS  = $Config->{ADD_EMPTY_PASS};
    my $SSL_CHECK       = $Config->{SSL_CHECK};
    my $SSL_CA_PATH     = $Config->{SSL_CA_PATH};
    my $TIMEOUT         = $Config->{TIMEOUT};
    my $CLIENTATTRIBUTE = $Config->{CLIENTATTRIBUTE};
    my $POLL            = $Config->{POLL};
    my $poll_timeout    = $Config->{POLL_TIMEOUT};
    my $poll_interval   = $Config->{POLL_INTERVAL};

    my $debug   = false;
    if ( $Config->{Debug} =~ /true/i ) {
        $debug = true;
    }
   
    my $check_ssl = false;
    if ( $Config->{SSL_CHECK} =~ /true/i ) {
        $check_ssl = true;
    }

    my $timeout = $Config->{TIMEOUT};

    # if there exists an auth-type config may overwrite this
    my $auth_type = $RAD_CONFIG{"Auth-Type"};
    try {
        &radiusd::radlog( Info, "Looking for config for auth-type $auth_type");
        if ( ( $cfg_file->val( $auth_type, "URL") )) {
            $URL = $cfg_file->val( $auth_type, "URL" );
            &radiusd::radlog(Debug, "Overwriting URL to ". $URL ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "REALM") )) {
            $REALM = $cfg_file->val( $auth_type, "REALM" );
            &radiusd::radlog(Debug, "Overwriting REALM to ". $REALM ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "RESCONF") )) {
            $RESCONF = $cfg_file->val( $auth_type, "RESCONF" );
            &radiusd::radlog(Debug, "Overwriting RESCONF to ". $RESCONF ." based on auth-type: ". $auth_type);
        }

        if ( ( $cfg_file->val( $auth_type, "DEBUG") )) {
            $debug = $cfg_file->val( $auth_type, "DEBUG" );
            &radiusd::radlog(Debug, "Overwriting DEBUG to ". $debug ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "SPLIT_NULL_BYTE") )) {
            $Config->{SPLIT_NULL_BYTE} = $cfg_file->val( $auth_type, "SPLIT_NULL_BYTE" );
            &radiusd::radlog(Debug, "Overwriting SPLIT_NULL_BYTE to ". $Config->{SPLIT_NULL_BYTE} ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "ADD_EMPTY_PASS") )) {
            $Config->{ADD_EMPTY_PASS} = $cfg_file->val( $auth_type, "ADD_EMPTY_PASS" );
            &radiusd::radlog(Debug, "Overwriting ADD_EMPTY_PASS to ". $Config->{ADD_EMPTY_PASS} ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "SSL_CHECK") )) {
            $check_ssl = $cfg_file->val( $auth_type, "SSL_CHECK" );
            &radiusd::radlog(Debug, "Overwriting SSL_CHECK to ". $check_ssl ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "SSL_CA_PATH") )) {
            $Config->{SSL_CA_PATH} = $cfg_file->val( $auth_type, "SSL_CA_PATH" );
            &radiusd::radlog(Debug, "Overwriting SSL_CA_PATH to ". $Config->{SSL_CA_PATH} ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "TIMEOUT") )) {
            $timeout = $cfg_file->val( $auth_type, "TIMEOUT" );
            &radiusd::radlog(Debug, "Overwriting TIMEOUT to ". $timeout ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "CLIENTATTRIBUTE") )) {
            $Config->{CLIENTATTRIBUTE} = $cfg_file->val( $auth_type, "CLIENTATTRIBUTE" );
            &radiusd::radlog(Debug, "Overwriting CLIENTATTRIBUTE to ". $Config->{CLIENTATTRIBUTE} ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "POLL") )) {
            $POLL = $cfg_file->val( $auth_type, "POLL" );
            &radiusd::radlog(Debug, "Overwriting POLL to ". $POLL ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "POLL_TIMEOUT") )) {
            $poll_timeout = $cfg_file->val( $auth_type, "POLL_TIMEOUT" );
            &radiusd::radlog(Debug, "Overwriting POLL_TIMEOUT to ". $poll_timeout ." based on auth-type: ". $auth_type);
        }
        if ( ( $cfg_file->val( $auth_type, "POLL_INTERVAL") )) {
            $poll_interval = $cfg_file->val( $auth_type, "POLL_INTERVAL" );
            &radiusd::radlog(Debug, "Overwriting POLL_INTERVAL to ". $poll_interval ." based on auth-type: ". $auth_type);
        }
    }
    catch {
        &radiusd::radlog( Info, "Warning: $@" );
    };

    my $poll_enabled = false;
    if ( defined($POLL) && $POLL =~ /true/i ) {
        $poll_enabled = true;
    }

 	&radiusd::radlog( Info, "Debugging config: ". $Config->{Debug});
    	&radiusd::radlog( Info, "Verifying SSL certificate: ". $Config->{SSL_CHECK} );
    	&radiusd::radlog( Info, "Default URL $URL " );

    if ( $debug == true ) {
        &log_request_attributes;
    }

    my %params = ();

    # put RAD_REQUEST members in the privacyIDEA request
    if ( exists( $RAD_REQUEST{'State'} ) ) {
        my $hexState = $RAD_REQUEST{'State'};
        if ( substr( $hexState, 0, 2 ) eq "0x" ) {
            $hexState = substr( $hexState, 2 );
        }
        $params{'state'} = pack 'H*', $hexState;
    }
    if ( exists( $RAD_REQUEST{'User-Name'} ) ) {
        $params{"user"} = $RAD_REQUEST{'User-Name'};
    }
    if ( exists( $RAD_REQUEST{'Stripped-User-Name'} )) {
        $params{"user"} = $RAD_REQUEST{'Stripped-User-Name'};
    }

    if ( exists( $RAD_REQUEST{'User-Password'} ) ) {
        my $password = $RAD_REQUEST{'User-Password'};
        if ( $Config->{SPLIT_NULL_BYTE} =~ /true/i ) {
            my @p = split(/\0/, $password);
            $password = @p[0];
        }
        # Decode password (from <https://perldoc.perl.org/Encode::Guess#Encode::Guess-%3Eguess($data)>)
        my $decoder = Encode::Guess->guess($password);
        if ( ! ref($decoder) ) {
            radiusd::radlog( Info, "Could not find valid password encoding. Sending password as-is." );
            radiusd::radlog( Debug, $decoder );
        } else {
            &radiusd::radlog( Info, "Password encoding guessed: " . $decoder->name);
            $password = $decoder->decode($password);
        }
        $params{"pass"} = $password;
    } elsif ( $Config->{ADD_EMPTY_PASS} =~ /true/i ) {
        $params{"pass"} = "";
    }

    # We need to decode the username as well since it might contain special chars
    if ( exists( $params{"user"} ) ) {
        my $decoder = Encode::Guess->guess($params{"user"});
        if ( ! ref($decoder) ) {
            radiusd::radlog( Info, "Could not find valid username encoding. Sending username as-is." );
            radiusd::radlog( Debug, $decoder );
        } else {
            &radiusd::radlog( Info, "Username encoding guessed: " . $decoder->name);
            $params{"user"} = $decoder->decode($params{"user"});
        }
    }

    # Security enhancement sned Message-Authenticator back
    if ( exists( $RAD_REQUEST{'Message-Authenticator'} )) {
        $RAD_REPLY{'Message-Authenticator'} = $RAD_REQUEST{'Message-Authenticator'};
    }

    # URL encode username and password
    my $uri = URI::Encode->new( { encode_reserved => 0 } );
    $params{"user"} = $uri->encode($params{"user"});
    $params{"pass"} = $uri->encode($params{"pass"});
    if ( exists( $RAD_REQUEST{'NAS-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'NAS-IP-Address'};
        &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
    } elsif ( exists( $RAD_REQUEST{'Packet-Src-IP-Address'} ) ) {
        $params{"client"} = $RAD_REQUEST{'Packet-Src-IP-Address'};
        &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
    }
    if (exists ( $Config->{CLIENTATTRIBUTE} ) ) {
        if ( exists( $RAD_REQUEST{$Config->{CLIENTATTRIBUTE}} ) ) {
            $params{"client"} = $RAD_REQUEST{$Config->{CLIENTATTRIBUTE}};
            &radiusd::radlog( Info, "Setting client IP to $params{'client'}." );
        }
    }
    if ( length($REALM) > 0 ) {
        $params{"realm"} = $REALM;
    } elsif ( length($RAD_REQUEST{'Realm'}) > 0 ) {
        $params{"realm"} = $RAD_REQUEST{'Realm'};
    }
    if ( length($RESCONF) > 0 ) {
        $params{"resConf"} = $RESCONF;
    }

    &radiusd::radlog( Info, "Auth-Type: $auth_type" );
    &radiusd::radlog( Info, "url: $URL" );
    &radiusd::radlog( Info, "user sent to privacyidea: $params{'user'}" );
    &radiusd::radlog( Info, "realm sent to privacyidea: $params{'realm'}" );
    &radiusd::radlog( Info, "resolver sent to privacyidea: $params{'resConf'}" );
    &radiusd::radlog( Info, "client sent to privacyidea: $params{'client'}" );
    &radiusd::radlog( Info, "state sent to privacyidea: $params{'state'}" );
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "urlparam $_ = $params{$_}\n" )
        for ( keys %params );
    }
    else {
        &radiusd::radlog( Info, "urlparam $_ \n" ) for ( keys %params );
    }

    my $ua = LWP::UserAgent->new();
    $ua->env_proxy;
    $ua->timeout($timeout);
    &radiusd::radlog( Info, "Request timeout: $timeout " );
    # Set the user-agent to be fetched in privacyIDEA Client Application Type
    $ua->agent("FreeRADIUS");
    if ($check_ssl == false) {
        try {
            # This is only availble with LWP version 6
            &radiusd::radlog( Info, "Not verifying SSL certificate!" );
            $ua->ssl_opts( verify_hostname => 0, SSL_verify_mode => 0x00 );
        } catch {
            &radiusd::radlog( Error, "ssl_opts only supported with LWP 6. error: $_" );
        }
    } else {
        try {
            &radiusd::radlog( Info, "Verifying SSL certificate!" );
            if ( exists( $Config->{SSL_CA_PATH} ) ) {
                if ( length $SSL_CA_PATH ) {
                    &radiusd::radlog( Info, "SSL_CA_PATH: $SSL_CA_PATH" );
                    $ua->ssl_opts(
                        SSL_ca_path => $SSL_CA_PATH,
                        verify_hostname => 1
                    );
                }
                else {
                    &radiusd::radlog( Info,
                        "Verifying SSL certificate against system wide CAs!" );
                    $ua->ssl_opts( verify_hostname => 1 );
                }
            }
        }
        catch {
            &radiusd::radlog( Error,
                "Something went wrong setting up SSL certificate verification: $_" );
        }
    }

    my $starttime = [gettimeofday];
    my $response = $ua->post( $URL, \%params );
    my $content  = $response->decoded_content();
    my $elapsedtime = tv_interval($starttime);
    &radiusd::radlog( Info, "elapsed time for privacyidea call: $elapsedtime" );
    if ( $debug == true ) {
        &radiusd::radlog( Debug, "Content $content" );
    }
    $RAD_REPLY{'Reply-Message'} = "privacyIDEA server denied access!";
    my $g_return = RLM_MODULE_REJECT;

    if ( !$response->is_success ) {
        # This was NO OK 200 response
        my $status = $response->status_line;
        &radiusd::radlog( Info, "privacyIDEA request failed: $status" );
        $RAD_REPLY{'Reply-Message'} = "privacyIDEA request failed: $status";
        $g_return = RLM_MODULE_FAIL;
    }
    try {
        my $coder = JSON->new->ascii->pretty->allow_nonref;
        my $decoded = $coder->decode($content);
        my $message = $decoded->{detail}{message};
        if ( $decoded->{result}{value} ) {
            &radiusd::radlog( Info, "privacyIDEA access granted for $params{'user'} realm='$params{'realm'}'" );
            $RAD_REPLY{'Reply-Message'} = "privacyIDEA access granted";
            # Add the response hash to the Radius Reply
            %RAD_REPLY = ( %RAD_REPLY, mapResponse($decoded));
            $g_return = RLM_MODULE_OK;
        }
        elsif ( $decoded->{result}{status} ) {
            &radiusd::radlog( Info, "privacyIDEA Result status is true!" );
            $RAD_REPLY{'Reply-Message'} = $decoded->{detail}{message};
            if ( $decoded->{detail}{transaction_id} ) {
                my $transaction_id = $decoded->{detail}{transaction_id};
                my $client_mode = $decoded->{detail}{client_mode} || "";
                # Only poll for a genuine push *authentication* challenge. An
                # enrollment-via-multichallenge push also has client_mode "poll"
                # but carries a QR/link the client must see, so it must take the
                # normal challenge path instead of being polled away.
                if ( $poll_enabled == true && $client_mode eq "poll"
                     && !$decoded->{detail}{enroll_via_multichallenge} ) {
                    ## Push token: poll privacyIDEA for confirmation instead of
                    ## returning an Access-Challenge. This avoids showing the user
                    ## an empty input field for a token that expects no input.
                    ## NOTE: this blocks the FreeRADIUS worker thread for up to
                    ## POLL_TIMEOUT seconds (see poll_push).
                    $g_return = poll_push( $ua, $URL, \%params, $decoded,
                                           $poll_timeout, $poll_interval );
                } else {
                    ## we are in challenge response mode:
                    ## 1. split the response in fail, state and challenge
                    ## 2. show the client the challenge and the state
                    ## 3. get the response and
                    ## 4. submit the response and the state to linotp and
                    ## 5. reply ok or reject
                    $RAD_REPLY{'State'} = $transaction_id;
                    $RAD_CHECK{'Response-Packet-Type'} = "Access-Challenge";
                    # Add the response hash to the Radius Reply
                    %RAD_REPLY = ( %RAD_REPLY, mapResponse($decoded));
                    $g_return  = RLM_MODULE_HANDLED;
                }
            } else {
                &radiusd::radlog( Info, "privacyIDEA access denied for $params{'user'} realm='$params{'realm'}'" );
                #$RAD_REPLY{'Reply-Message'} = "privacyIDEA access denied";
                $g_return = RLM_MODULE_REJECT;
            }
        }
        elsif ( !$decoded->{result}{status}) {
            # An internal error occurred. We use the original return value RLM_MODULE_FAIL
            &radiusd::radlog( Info, "privacyIDEA Result status is false!" );
            $RAD_REPLY{'Reply-Message'} = $decoded->{result}{error}{message};
            &radiusd::radlog( Info, $decoded->{result}{error}{message});
            my $errorcode = $decoded->{result}{error}{code};
            if ($errorcode == 904) {
                $g_return = RLM_MODULE_NOTFOUND;
            } else {
                $g_return = RLM_MODULE_FAIL;
            }
            &radiusd::radlog( Info, "privacyIDEA failed to handle the request" );
        }
    } catch {
        my $e = shift;
        &radiusd::radlog( Info, "$e");
        &radiusd::radlog( Info, "Can not parse response from privacyIDEA." );
    };

    &radiusd::radlog( Info, "return $ret_hash->{$g_return}" );
    return $g_return;

}

sub log_request_attributes {
    # This shouldn't be done in production environments!
    # This is only meant for debugging!
    for ( keys %RAD_REQUEST ) {
        &radiusd::radlog( Debug, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}" );
    }
}


# Function to handle authorize
sub authorize {

    # For debugging purposes only
    # &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle preacct
sub preacct {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {

    # For debugging purposes only
    #       &log_request_attributes;

    # You can call another subroutine from here
    &test_call;

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {

    # For debugging purposes only
    #       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {

    # For debugging purposes only
    #       &log_request_attributes;

    # Loads some external perl and evaluate it
    my ( $filename, $a, $b, $c, $d ) = @_;
    &radiusd::radlog( 1, "From xlat $filename " );
    &radiusd::radlog( 1, "From xlat $a $b $c $d " );
    local *FH;
    open FH, $filename or die "open '$filename' $!";
    local ($/) = undef;
    my $sub = <FH>;
    close FH;
    my $eval = qq{ sub handler{ $sub;} };
    eval $eval;
    eval { main->handler; };
}

# Function to handle detach
sub detach {

    # For debugging purposes only
    #       &log_request_attributes;

    # Do some logging.
    &radiusd::radlog( 0, "rlm_perl::Detaching. Reloading. Done." );
}

#
# Some functions that can be called from other functions
#

sub test_call {

    # Some code goes here
}

1;
