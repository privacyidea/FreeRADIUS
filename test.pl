#!/usr/bin/perl

use strict;
use warnings;

use Sub::Override;
use Test::LWP::UserAgent;
use Test::More;

use Capture::Tiny ':all';

use JSON qw(encode_json);

use lib '.';

# ==========================================
# Define Global Variables expected by rlm_perl
# ==========================================
our %RAD_REQUEST;
our %RAD_REPLY;
our %RAD_CHECK;
our %RAD_CONFIG;
our %RAD_PERLCONF;

# ==========================================
# Mock the radiusd package
# ==========================================
{
    package radiusd;

    # Simple print logger to replace radiusd::radlog
    sub radlog {
        my ($level, $msg) = @_;
        # Map levels to strings if necessary, usually they are integers
        print "[radiusd LOG] ($level): $msg\n";
    }
}

# Set up configuration expected by privacyidea_radius.pm
# This mimics what would be in radiusd.conf or passed via %RAD_PERLCONF
$RAD_PERLCONF{'configfile'} = "rlm_perl.ini";

# Mock the HTTP call to privacyIDEA
my $mock_ua = Test::LWP::UserAgent->new;

# Simulating a successful PrivacyIDEA response
my $json_response = {
    result => {
        status => "true",
        value => "true",
        authentication => "ACCEPT",
    },
    detail => {
        message => "matching 1 tokens",
        otplen => 6,
        serial =>  "TOTP00003913",
        threadid => 140259533518592,
        type => "totp",
        user => {
            email => "",
            givenname => "testuser",
        }
    }
};
my $res =  HTTP::Response->new( 200, "OK", ['Content-Type' => 'application/json'],
    encode_json( $json_response ) );
$mock_ua->map_response( qr{localhost/validate/check}, $res );

# ==========================================
# Load the plugin
# ==========================================
use_ok( 'privacyidea_radius' );

# ==========================================
# Configure the test environment
# ==========================================
# Set up a sample request
$RAD_REQUEST{'User-Name'} = "testuser";
$RAD_REQUEST{'User-Password'} = "testpassword";
$RAD_REQUEST{'NAS-IP-Address'} = "192.0.2.23";

# TODO: Check for config overwrite with different Auth-Type
#$RAD_CONFIG{'Auth-Type'} = "piPerl";

# ==========================================
# Run the Authentication
# ==========================================

# Call the authenticate subroutine defined in privacyidea_radius.pm
{
    # make LWP return it inside our code (from https://stackoverflow.com/a/39204432)
    my $sub = Sub::Override->new(
        'LWP::UserAgent::new'=> sub { return $mock_ua }
    );
    # To print the log output to stdout during testing use tee_stdout
    my ( $stdout, $result ) = capture_stdout \&authenticate;
    like ( $stdout, qr{Request URL: https://localhost/validate/check}, "Check for correct URL in log output" );
    is ( $result, 2, 'Authentication result should be 2 (RLM_MODULE_OK).' );
    ok ( exists $RAD_REPLY{'Reply-Message'}, 'Check Reply-Message attribute in RAD_REPLY.');
    is ( $RAD_REPLY{'Reply-Message'}, "privacyIDEA access granted", "Check Reply-Message attribute contents." );
}

is( preacct(), 2, 'Check "preacct" function in script (Should return RLM_MODULE_OK).' );

done_testing()
