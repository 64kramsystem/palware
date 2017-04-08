#!/usr/bin/env ruby

class MadConvertIdaSourceToNasm

  # Numbers are set where the order is required.
  #
  REGEXES = {
    /seg000:/ => '',                       # 1.
    /\w+( +org.*)/ => '     \1',           # 2.

    # We can't use the "Holy ****" regex to remove duplicated addresses, because lines of
    # cases 2->6 precede the code, but we want the address to be kept on the code (which
    # is the second, or even later, match), not on the preceding line.

    /^\w+$/         => '',                 # 3. address, without anything
    /^\w+ (\S+:)/   => "\\1     ",         # 4. label
    /^\w+ (; -+)/   => '\1-----',          # 5. separator (-)
    /^\w+ (; =.*)/  => '\1=====',          # 6. separator (=)
    /^\w+ ( +;.*)/  => '     \1',          # 7. comment only
    /^(\w+)  (.*)/  => 'l\1:\2',           # 8. anything else

    /.*public start\n/     => '',
    /.*start.*proc near\n/ => '',
    /.*start +endp\n/      => '',
    /.*seg\d+ +ends\n/     => '',
    /.*assume .s:.*\n/     => '',

    # Holy ****!!
    #
    # Explanation:
    # - for all the lines which start with the first group, and have other content,
    # - followed by one or more other lines, with the same first group and any other content,
    # - replace all the first groups (except the one at the beginning of the match) with spaces
    #
    /(^\w+:)(.*\n)(\1(.*\n))+/ => ->(match) { match.gsub(/(?<!\A)#{$1}/, ' ' * $1.size) },

    # Code changes

    /ptr /          => '',
    # /test    byte / => 'test    ',       # implicit in value
    # /cmp     byte / => 'cmp     ',       # ^^
    /(j\w+ +short )near /   => '\1',
    /jmp     far /  => 'jmp     ',

    # /(test|cmp)( +)\[/ => '\1\2byte [',  # must be explicit

    /([c-g]s:[\w_+-]+)/ => '[\1]',         # 1. eg. 'cs:loc_123-ABCh' => '[cs:loc_123-ABCh]'
    /([c-g])s:\[/       => '[\1s:',        # 2. eg. 'es:[di]' => '[es:di]'
    /\[ds:/             => '[',            # 3. generates redundant opcode

    // => '↑',
    //  => '↓',

    /(\w+) dup\((\w+)\)/   => "times \\1 db \\2",
    /, (times \w+ db \w+)/ => "\n                     \\1",
    /(times \w+ db \w+), / => "\\1\n                     db ",
  }

  def execute(filename)
    content = IO.read(filename)

    REGEXES.each do |source, destination|
      if destination.is_a?(Proc)
        content.gsub!(source, &destination)
      else
        content.gsub!(source, destination)
      end
    end

    IO.write(filename, content)
  end
end

if __FILE__ == $0
  if ARGV.size != 1 || ARGV == ['-h'] || ARGV == ['--help']
    puts "Performs a mad regex conversion from an IDA Pro disassembly to a NASM compatible one."
    puts "The header (~25/30 lines) need to be removed, except the `org` statement."
    puts
    puts "Usage: convert_ida_to_nasm.rb <filename>"
    exit
  end

  MadConvertIdaSourceToNasm.new.execute(ARGV[0])
end
