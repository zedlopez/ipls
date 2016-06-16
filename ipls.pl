#!/usr/bin/env perl
use strict;
use warnings;

# sudo iptables -L -n -v --line-numbers|./ipls.pl -

use IPTables::Parse;
use Text::Table::Tiny qw/generate_table/;
$Text::Table::Tiny::HEADER_CORNER_MARKER = '+';
$Text::Table::Tiny::HEADER_ROW_SEPARATOR = '-';
our ($temp, $table);

if ((defined $ARGV[0]) && ($ARGV[0] eq '-')) {
my $input = do {local $/; <>};
    use File::Temp;
    $temp  = File::Temp->new(TEMPLATE =>'iptablesXXXXXX');
    print $temp $input;
}
else {
$table = shift @ARGV;
}

$table ||= 'filter';

our @column_names = (qw(num int out prot src dest state target extended comment));

sub any (&@) {
  my $f = shift;
  for (@_) {
    return 1 if $f->();
  }
  return 0;
}

sub process_rule {
  my $rule = shift;
  my $int = ($rule->{intf_in} eq '*') ? '' : $rule->{intf_in};
  my $ext = ($rule->{intf_out} eq '*') ? '' : $rule->{intf_out};
  my $source = ($rule->{src} eq '0.0.0.0/0') ? '' : $rule->{src};
  $source .= ":".$rule->{s_port} if $rule->{s_port};
  my $dest = ($rule->{dst} eq '0.0.0.0/0') ? '' : $rule->{dst};
  $dest .= ":".$rule->{d_port} if $rule->{d_port};
  my $prot = ($rule->{protocol} eq 'all') ? '' : $rule->{protocol};
  my $state = $rule->{state};
  my $extended = $rule->{extended};
  my @res = (qr/^\s+/, qr/\s+$/);
  unshift @res, qr/\bstate $state\b/ if $state;
  unshift @res, qr/\breject-with icmp-port-unreachable\b/ if ($rule->{target} eq 'REJECT') && $prot && ($prot ne 'icmp');
  if ($rule->{d_port}) {
    my $dstr = join '', 'dpt', (($rule->{d_port} =~ /:/) ? 's' : ''), ':', $rule->{d_port};
    my $re = qr/\b$rule->{protocol}\s+$dstr\b/;
    unshift @res, $re;
  }
  $extended =~ s{$_}{} for @res;
  $extended =~ s{\s+}{ }g;
  return [$rule->{rule_num}, $int, $ext, $prot, $source, $dest, $state, $rule->{target},$extended,$rule->{comment}];
}

sub assign {
  my ($columns,$listref) = @_;
  for (my $i=0; $i < @$listref; $i++) {
    push @{$columns->{$column_names[$i]}}, $listref->[$i];
  }
}

sub process_chain {
  my $rules = shift;
  my %columns;
  $columns{$_} = [] for @column_names;


  for my $rule (@$rules) {
    assign(\%columns,process_rule($rule));
  }
  my $matrix = [];

  for my $column (@column_names) {
    push @$matrix, [ $column, @{$columns{$column}} ] if (any { defined $_ and $_ =~ /\S/ } @{$columns{$column}});
  }
  return undef unless scalar @$matrix;
  my @transposed;
  my $lc = $#{$matrix->[0]};
  for my $col (0..$lc) {
    push @transposed, [map $_->[$col], @$matrix];
  }
  return \@transposed;

}

my %opt;
if ($temp) {
    $opt{ipt_rules_file} = $temp;
}
elsif ($<) {
    die "Must be run as root\n";
}    
my $ipt = IPTables::Parse->new(%opt);

my $chains = $ipt->list_table_chains($table);

my @output;
for my $chain (@$chains) {
  my $rules = $ipt->chain_rules($table, $chain);
  my $policy = $ipt->chain_policy($table, $chain);
  $chain = join ' ', $chain, "(policy: $policy)" if $policy;
  push @output, $chain;
  my $rows = process_chain($rules);
  push @output, +(defined $rows) ? generate_table(rows => process_chain($rules), header_row => 1, separate_rows => 1) : "No rules";
  push @output, '';
}
print join  "\n", @output;
