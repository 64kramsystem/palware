#!/usr/bin/env ruby

class MadConvertIdaSourceToNasm

  # The global effect is to move the text to 5 columns to the left; `seg000:` is -7, and
  # `l`/`:` are +2.
  #
  # Numbers are set where the order is required.
  #
  REGEXES = {
    /seg000:/ => '',                       # 1.
    /\w+( +org.*)/ => '    \1',            # 2.

    # We can't use the "Holy ****" regex to remove duplicated addresses, because lines of
    # cases 2->6 precede the code, but we want the address to be kept on the code (which
    # is the second, or even later, match), not on the preceding line.

    /^\w+$/         => '',                 # 3. address, without anything
    /^\w+ (\w+)( +d[bwd])/ => '\1:    \2', # 4. string identifier: currently, the address is removed
    /^\w+ (\S+:)/   => '\1     ',          # 5. label
    /^\w+ (; -+)/   => '\1-----',          # 6. separator (-)
    /^\w+ (; =.*)/  => '\1=====',          # 7. separator (=)
    /^\w+ ( *;.*)/  => '     \1',          # 8. comment only
    /^(\w+)  (.*)/  => 'l\1:\2',           # 9. anything else

    /.*public start\n/     => '',
    /.*end start$\n?/      => '',
    /.*start +proc (near|far)\n/ => '',
    /.* +endp( +;.*)?\n/   => '',
    /.*seg\d+ +ends\n/     => '',
    /.*assume .s:.*\n/     => '',

    /.*?(\w+) +proc near( +;.*)?$/ => '     \1:\2',

    # Holy ****!!
    #
    # Explanation:
    # - for all the lines which start with the first group, and have other content,
    # - followed by one or more other lines, with the same first group and any other content,
    # - replace all the first groups (except the one at the beginning of the match) with spaces
    #
    /(^\w+:)(.*\n)(\1(.*\n))+/ => ->(match) { match.gsub(/(?<!\A)#{$1}/, ' ' * $1.size) },

    # Code changes

    # Add the implicit `ds:`; in the brackets/segments stage, `ds:` is removed, and the
    # square brackets added.
    # If we added the square brackets here, then we should ignore this case at the B/S
    # stage.
    #
    # `mov byte ptr aASuriv101, al` => `mov byte ptr ds:aASuriv101, al`
    #
    # Note that we don't do this for `jmp near ptr`.
    #
    # After, just remove all the rest of `ptr`.
    #
    /(jmp +near )ptr / => '\1',
    /ptr (\w+{3,})/ => 'ptr ds:\1',
    /ptr / => '',

    # Do something similar:
    #
    # `mov word_13E, cs` => `mov ds:word_13E, cs`
    #
    # we do it in a restricted way, for now.
    #
    /(mov +)(word_)/ => '\1ds:\2',

    # Square brackets/segment regs handling

    /([c-e]s:[\w_+-]+)/ => '[\1]',         # 1. eg. 'cs:loc_123-ABCh' => '[cs:loc_123-ABCh]'
    /([c-e])s:\[/       => '[\1s:',        # 2. eg. 'es:[di]' => '[es:di]'
    /\[ds:/             => '[',            # 3. generates redundant opcode

    # /test    byte / => 'test    ',       # implicit in value
    # /cmp     byte / => 'cmp     ',       # ^^
    /(j\w+ +short )near /   => '\1',
    /jmp     far /  => 'jmp     ',

    # We need to introduce smarts here. When jumping on a dword value, the 'far' is
    # implicit, so we need to make it explicit.
    #
    /(jmp|call)( +)([c-e]s:dword_)/ => '\1\2far \3',

    # /(test|cmp)( +)\[/ => '\1\2byte [',  # must be explicit

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
