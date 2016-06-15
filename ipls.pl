#!/usr/bin/env perl
use strict;
use warnings;
$|=1;
use IPTables::Parse;
use Text::Table::Any;
use Data::Dumper;
my $table = shift @ARGV || 'filter';

my %columns;
my @column_names = (qw(num int out src dest state target extended comment));
for (my $i = 0; $i < @column_names; $i++) {
  $columns{$column_names[$i]} = $i;
}

sub process_chain {
  my $rules = shift;
  my @result;
  for my $rule (@$rules) {
    push @result, [$rule->{rule_num}, $rule->{intf_in}, (($rule->{intf_out} eq '*') ? '' : $rule->{intf_out}), (join ':', $rule->{src}, $rule->{s_port}), (join ':', $rule->{dst}, $rule->{d_port}), $rule->{state}, $rule->{target}, $rule->{extended}, $rule->{comment}]
  }
  # construct a column centric view, keeping columns iff one is non-blank, turn it back into a row-centric view at the end
  my @include;
  COL: for (my $i = 0; $i < @column_names; $i++) {
    for my $row (@result) {
      if (defined $row->[$i] and $row->[$i] =~ /\S/) {
        $include[$i] = $i;
        next COL;
      }
    }
  }
  my %diff;
  @diff{values %columns} = (1) x scalar @column_names;
  delete @diff{@include};
my  @exclude = reverse sort keys %diff;
  unshift @result, \@column_names;
  my @real;
  for my $i (@exclude) {
    for (my $j =0; $j < @result; $j++) {
      splice @{$result[$j]}, $i, 1;
    }
  }
  return \@result;
}

die "Must be root" if $<;

my $ipt = IPTables::Parse->new;
my $chains = $ipt->list_table_chains($table);

for my $chain (@$chains) {
    my $rules = $ipt->chain_rules($table, $chain);
    print "$chain\n"; # policy
    my $rows = process_chain($rules);
    print +(scalar @{$rows->[0]}) ? Text::Table::Any::table(rows => process_chain($rules), header_row => 1) : "No rules\n";
  }
  
