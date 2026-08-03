#!/usr/bin/perl
# Unit tests for the push-poll logic in privacyidea_radius.pm.
# Runs without FreeRADIUS: stubs radiusd::radlog and injects a fake LWP UA into
# poll_push()/finalize_transaction() (which take the UA as an argument).
#
#   prove -v tests/poll.t     (from the repo root)
use strict;
use warnings;
use Test::More;

# Stub the FreeRADIUS logging symbol used throughout the module.
no warnings 'once';
*radiusd::radlog = sub { };

# Load the module (defines subs + RLM_MODULE_* constants in main::).
my $ok = eval { require "./privacyidea_radius.pm"; 1 };
ok($ok, "module loads") or BAIL_OUT("could not load module: $@");

# ---- fake LWP::UserAgent -------------------------------------------------
package FakeResp;
sub new { my ($c, %a) = @_; bless {%a}, $c }
sub is_success { $_[0]->{ok} }
sub decoded_content { $_[0]->{body} }
sub status_line { $_[0]->{status} || "500 err" }

package FakeUA;
# get() pops from a scripted queue; post() returns a fixed finalize response.
sub new { my ($c, @get) = @_; bless { get => [@get], post => undef }, $c }
sub set_post { $_[0]->{post} = $_[1]; return $_[0] }
sub get  { my $s = shift; shift @{$s->{get}} }
sub post { my $s = shift; $s->{post} }

package main;

my $pending  = '{"detail":{"challenge_status":"pending"},"result":{"status":true,"value":false}}';
my $accept   = '{"detail":{"challenge_status":"accept"},"result":{"status":true,"value":true}}';
my $declined = '{"detail":{"challenge_status":"declined"},"result":{"status":true,"value":false}}';
my $finalok  = '{"detail":{"message":"Found matching challenge"},"result":{"status":true,"value":true}}';
my $finalno  = '{"detail":{"message":"nope"},"result":{"status":true,"value":false}}';

my $URL = "https://localhost/validate/check";
my %params = (user => "alice");

sub reset_reply { %main::RAD_REPLY = (); %main::RAD_CHECK = (); }

# poll_push takes the decoded initial-check response; build a minimal one.
sub decoded_with_tx { return { detail => { transaction_id => $_[0] } } }

# 1) pending -> accept -> finalize -> OK
reset_reply();
{
    my $ua = FakeUA->new(FakeResp->new(ok => 1, body => $pending),
                         FakeResp->new(ok => 1, body => $accept))->set_post(
                         FakeResp->new(ok => 1, body => $finalok));
    is(main::poll_push($ua, $URL, \%params, decoded_with_tx("TX1"), 10, 1), RLM_MODULE_OK(),
       "pending then accept -> finalize -> OK");
}

# 2) declined -> REJECT (and stops polling)
reset_reply();
{
    my $ua = FakeUA->new(FakeResp->new(ok => 1, body => $declined));
    is(main::poll_push($ua, $URL, \%params, decoded_with_tx("TX2"), 10, 1), RLM_MODULE_REJECT(),
       "declined -> REJECT");
}

# 3) timeout (always pending) -> HANDLED (challenge) with State set
reset_reply();
{
    my $ua = FakeUA->new(FakeResp->new(ok => 1, body => $pending),
                         FakeResp->new(ok => 1, body => $pending),
                         FakeResp->new(ok => 1, body => $pending));
    is(main::poll_push($ua, $URL, \%params, decoded_with_tx("TX3"), 2, 1), RLM_MODULE_HANDLED(),
       "timeout -> Access-Challenge");
    is($main::RAD_REPLY{'State'}, "TX3", "timeout sets State to transaction_id");
}

# 4) finalize where privacyIDEA denies -> REJECT
reset_reply();
{
    my $ua = FakeUA->new()->set_post(FakeResp->new(ok => 1, body => $finalno));
    is(main::finalize_transaction($ua, $URL, \%params, "TX4"), RLM_MODULE_REJECT(),
       "finalize with value=false -> REJECT");
}

# 5) finalize on transport failure -> FAIL (not REJECT) for an already-confirmed user
reset_reply();
{
    my $ua = FakeUA->new()->set_post(FakeResp->new(ok => 0, body => "<html>502</html>", status => "502 Bad Gateway"));
    is(main::finalize_transaction($ua, $URL, \%params, "TX5"), RLM_MODULE_FAIL(),
       "finalize on HTTP error -> FAIL");
}

# 6) poll URL derivation -- exercises the module's real poll_url(), incl. trailing slash
is(main::poll_url("https://pi.example/path/validate/check"),
   "https://pi.example/path/validate/polltransaction", "poll_url: plain");
is(main::poll_url("https://pi.example/validate/check/"),
   "https://pi.example/validate/polltransaction", "poll_url: trailing slash");

done_testing();
