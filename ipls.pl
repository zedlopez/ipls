#!/usr/bin/env perl
use strict;
use warnings;
use Data::Dumper;
# sudo iptables -L -n -v --line-numbers|./ipls.pl -
use List::Util qw/any/;
use lib "/home/zed/github/IPTables-Parse/lib";
use IPTables::Parse;

use first 'Text::ANSITable', 'Text::ASCIITable', 'Text::Table::Tiny';
# TODO: die if it doesn't find one?
my $tableclass = $first::module;

our ($table, $input);

if ((defined $ARGV[0]) && ($ARGV[0] eq '-')) {
  $input = do {local $/; <>};
} else {
  $table = shift @ARGV;
}

$table ||= 'filter';

our @column_names = (qw(int out prot src dest state target extended comment));
unshift @column_names, '#';

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
if ($input) {
  $opt{ipt_rules} = $input;
} elsif ($<) {
  die "Must be run as root\n";
}

my $ipt = IPTables::Parse->new(%opt);

my $chains = $ipt->list_table_chains($table);

my @output;
for my $chain (@$chains) {
  #  print "$chain";
  #  print Dumper(\@output);
  my $rules = $ipt->chain_rules($table, $chain);
  my $policy = $ipt->chain_policy($table, $chain);
  $chain = join ' ', $chain, "(policy: $policy)" if $policy;
  my $rows = process_chain($rules);
  if ($tableclass eq 'Text::Table::Tiny') {
    {
      no warnings 'once';
      $Text::Table::Tiny::HEADER_CORNER_MARKER = '+';
      $Text::Table::Tiny::HEADER_ROW_SEPARATOR = '-';
    }
    push @output, $chain;
    push @output, ((defined $rows) ? Text::Table::Tiny::generate_table(rows => $rows, header_row => 1, separate_rows => 1) : "No rules"), '';
    next;
  }
  binmode(STDOUT, ":utf8");
  my $columns = shift @$rows;
  #  print Dumper($columns);
  my $t;
  if ($tableclass eq 'Text::ASCIITable') {
    if (@$rows) {
      $t = Text::ASCIITable->new({headingText => $chain, headingAlign => 'left'});
      $t->setCols($columns);
      $t->addRow($rows);
    } else {
      $t =Text::ASCIITable->new;
      $t->setCols([$chain]);
      $t->addRow(["No rules"]);
    }
    push @output, $t->draw, '';
  }
  else { #Text::ANSITable
    if (@$rows) {
      $t = Text::ANSITable->new;
      $t->use_utf8(1);
      $t->use_box_chars(1);
      $t->border_style('Default::csingle');
      $t->apply_style_set(AltRow => {even_bgcolor => '333333'}); # TODO doesn't work
      $t->show_row_separator(1);
      $t->columns($columns);
      $t->set_column_style($_, align => 'right') for @{$t->columns};
      $t->rows($rows);
      push @output, $t->draw, '';
    } else {
      push @output, $chain, 'No rules', '';
    }
  }
}
print join  "\n", @output;

