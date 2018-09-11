# -*- coding: utf-8 -*- #

module Rouge
  module Lexers
    # IMPORTANT NOTICE:
    #
    # Please do not copy this lexer and open a pull request
    # for a new language. It will not get merged, you will
    # be unhappy, and kittens will cry.
    #
    class Solidity < RegexLexer
      title "Solidity"
      desc "Solidity, the browser scripting language"

      tag 'solidity'
      aliases 'sol'
      filenames '*.sol'
      mimetypes 'application/solidity', 'application/x-solidity',
                'text/solidity', 'text/x-solidity'

      def self.detect?(text)
        return 1 if text.shebang?('node')
        return 1 if text.shebang?('jsc')
        # TODO: rhino, spidermonkey, etc
      end

      state :multiline_comment do
        rule %r([*]/), Comment::Multiline, :pop!
        rule %r([^*/]+), Comment::Multiline
        rule %r([*/]), Comment::Multiline
      end

      state :comments_and_whitespace do
        rule /\s+/, Text
        rule %r(//.*?$), Comment::Single
        rule %r(/[*]), Comment::Multiline, :multiline_comment
      end

      state :expr_start do
        mixin :comments_and_whitespace

        rule %r(/) do
          token Str::Regex
          goto :regex
        end

        rule /[{]/ do
          token Punctuation
          goto :object
        end

        rule //, Text, :pop!
      end

      state :regex do
        rule %r(/) do
          token Str::Regex
          goto :regex_end
        end

        rule %r([^/]\n), Error, :pop!

        rule /\n/, Error, :pop!
        rule /\[\^/, Str::Escape, :regex_group
        rule /\[/, Str::Escape, :regex_group
        rule /\\./, Str::Escape
        rule %r{[(][?][:=<!]}, Str::Escape
        rule /[{][\d,]+[}]/, Str::Escape
        rule /[()?]/, Str::Escape
        rule /./, Str::Regex
      end

      state :regex_end do
        rule /[gim]+/, Str::Regex, :pop!
        rule(//) { pop! }
      end

      state :regex_group do
        # specially highlight / in a group to indicate that it doesn't
        # close the regex
        rule /\//, Str::Escape

        rule %r([^/]\n) do
          token Error
          pop! 2
        end

        rule /\]/, Str::Escape, :pop!
        rule /\\./, Str::Escape
        rule /./, Str::Regex
      end

      state :bad_regex do
        rule /[^\n]+/, Error, :pop!
      end

      def self.keywords
        @keywords ||= Set.new %w(
          anonymous as assembly break constant continue contract do delete
          else enum event external for function hex if indexed interface
          internal import is library mapping memory modifier new payable
          public pragma private return returns storage struct throw
          using var while constructor emit
        )
      end

      def self.keywords_type
#        return @keywords_type if @keywords_type
        @keywords_type = Set.new %w(
          int uint bytes fixed ufixed address bool
        )

        # bytes1 .. bytes32
        @keywords_type.merge( (1..32).map { |i| "bytes#{i}" } )

        # size helpers
        sizesm = (0..256).step(8)
        sizesn = (8..256).step(8)
        sizesmxn = sizesm.map { |m| m }
                     .product( sizesn.map { |n| n } )
                     .select { |m,n| m+n <= 256 }
        # [u]int8 .. [u]int256
        @keywords_type.merge( sizesn.map { |n|  "int#{n}" } )
        @keywords_type.merge( sizesn.map { |n| "uint#{n}" } )
        # [u]fixed{MxN}
        @keywords_type.merge(sizesmxn.map { |m,n|  "fixed#{m}x#{n}" })
        @keywords_type.merge(sizesmxn.map { |m,n| "ufixed#{m}x#{n}" })
      end


      def self.declarations
        @declarations ||= Set.new %w(
          var let const with function class
          extends constructor get set
        )
      end

      def self.reserved
        @reserved ||= Set.new %w(
          abstract after case catch default final in inline let
          match null of pure relocatable static switch try type
          typeof view
        )
      end

      def self.constants
        @constants ||= Set.new %w(wei finney szabo ether seconds minutes hours days weeks years)
      end

      def self.builtins
        @builtins ||= %w(
          true false
          assert require revert
          selfdestruct suicide
          this super balance transfer send call callcode delegatecall
          addmod mulmod keccak256 sha256 sha3 ripemd160 ecrecover
        )
      end

      def self.id_regex
        /[$a-z_][a-z0-9_]*/io
      end

      id = self.id_regex

      state :root do
        rule /\A\s*#!.*?\n/m, Comment::Preproc, :statement
        rule %r((?<=\n)(?=\s|/|<!--)), Text, :expr_start
        mixin :comments_and_whitespace
        rule %r(\+\+ | -- | ~ | && | \|\| | \\(?=\n) | << | >>>? | ===
               | !== )x,
          Operator, :expr_start
        rule %r([-<>+*%&|\^/!=]=?), Operator, :expr_start
        rule /[(\[,]/, Punctuation, :expr_start
        rule /;/, Punctuation, :statement
        rule /[)\].]/, Punctuation

        rule /`/ do
          token Str::Double
          push :template_string
        end

        rule /[?]/ do
          token Punctuation
          push :ternary
          push :expr_start
        end

        rule /(\@)(\w+)?/ do
          groups Punctuation, Name::Decorator
          push :expr_start
        end

        rule /[{}]/, Punctuation, :statement

        rule id do |m|
          if self.class.keywords.include? m[0]
            token Keyword
            push :expr_start
          elsif self.class.declarations.include? m[0]
            token Keyword::Declaration
            push :expr_start
          elsif self.class.keywords_type.include? m[0] 
            token Keyword::Type
          elsif self.class.reserved.include? m[0]
            token Keyword::Reserved
          elsif self.class.constants.include? m[0]
            token Keyword::Constant
          elsif self.class.builtins.include? m[0]
            token Name::Builtin
          else
            token Name::Other
          end
        end

        rule /[0-9][0-9]*\.[0-9]+([eE][0-9]+)?[fd]?/, Num::Float
        rule /0x[0-9a-fA-F]+/i, Num::Hex
        rule /0o[0-7][0-7_]*/i, Num::Oct
        rule /0b[01][01_]*/i, Num::Bin
        rule /[0-9]+/, Num::Integer

        rule /"/, Str::Double, :dq
        rule /'/, Str::Single, :sq
        rule /:/, Punctuation
      end

      state :dq do
        rule /[^\\"]+/, Str::Double
        rule /\\"/, Str::Escape
        rule /"/, Str::Double, :pop!
      end

      state :sq do
        rule /[^\\']+/, Str::Single
        rule /\\'/, Str::Escape
        rule /'/, Str::Single, :pop!
      end

      # braced parts that aren't object literals
      state :statement do
        rule /case\b/ do
          token Keyword
          goto :expr_start
        end

        rule /(#{id})(\s*)(:)/ do
          groups Name::Label, Text, Punctuation
        end

        rule /[{}]/, Punctuation

        mixin :expr_start
      end

      # object literals
      state :object do
        mixin :comments_and_whitespace

        rule /[{]/ do
          token Punctuation
          push
        end

        rule /[}]/ do
          token Punctuation
          goto :statement
        end

        rule /(#{id})(\s*)(:)/ do
          groups Name::Attribute, Text, Punctuation
          push :expr_start
        end

        rule /:/, Punctuation
        mixin :root
      end

      # ternary expressions, where <id>: is not a label!
      state :ternary do
        rule /:/ do
          token Punctuation
          goto :expr_start
        end

        mixin :root
      end

      # template strings
      state :template_string do
        rule /\${/, Punctuation, :template_string_expr
        rule /`/, Str::Double, :pop!
        rule /(\\\\|\\[\$`]|[^\$`]|\$(?!{))*/, Str::Double
      end

      state :template_string_expr do
        rule /}/, Punctuation, :pop!
        mixin :root
      end
    end
  end
end
