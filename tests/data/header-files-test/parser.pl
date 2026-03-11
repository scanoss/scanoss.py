#!/usr/bin/perl
# Copyright (c) 2024 The Perl Foundation
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the Artistic License 2.0.
#
# See https://opensource.org/licenses/Artistic-2.0
# for the full license text.

use strict;
use warnings;
use Getopt::Long;
use File::Basename;
use Carp qw(croak);

my $VERSION = '1.0.0';

sub new {
    my ($class, %args) = @_;
    my $self = bless {
        delimiter  => $args{delimiter}  || ',',
        quote_char => $args{quote_char} || '"',
        escape     => $args{escape}     || '\\',
        headers    => $args{headers}    || [],
        strict     => $args{strict}     // 1,
        line_num   => 0,
    }, $class;
    return $self;
}

sub parse_file {
    my ($self, $filename) = @_;
    croak "Filename required" unless defined $filename;

    open my $fh, '<:encoding(UTF-8)', $filename
        or croak "Cannot open '$filename': $!";

    my @records;
    my $header_line = <$fh>;
    chomp $header_line;
    $self->{headers} = $self->_split_line($header_line);
    $self->{line_num} = 1;

    while (my $line = <$fh>) {
        chomp $line;
        $self->{line_num}++;
        next if $line =~ /^\s*$/;
        next if $line =~ /^\s*#/;

        my $fields = $self->_split_line($line);
        if ($self->{strict} && scalar @$fields != scalar @{$self->{headers}}) {
            croak sprintf(
                "Field count mismatch at line %d: expected %d, got %d",
                $self->{line_num},
                scalar @{$self->{headers}},
                scalar @$fields
            );
        }

        my %record;
        for my $i (0 .. $#{$self->{headers}}) {
            $record{$self->{headers}[$i]} = $fields->[$i] // '';
        }
        push @records, \%record;
    }

    close $fh;
    return \@records;
}

sub _split_line {
    my ($self, $line) = @_;
    my @fields;
    my $field = '';
    my $in_quotes = 0;

    for my $char (split //, $line) {
        if ($char eq $self->{quote_char} && !$in_quotes) {
            $in_quotes = 1;
        } elsif ($char eq $self->{quote_char} && $in_quotes) {
            $in_quotes = 0;
        } elsif ($char eq $self->{delimiter} && !$in_quotes) {
            push @fields, $field;
            $field = '';
        } else {
            $field .= $char;
        }
    }
    push @fields, $field;

    return \@fields;
}

1;