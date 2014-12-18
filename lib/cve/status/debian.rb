require 'openssl'

# Debian's bug tracker uses Debian's CA
# There is probably a way to deal with this nicely, but for now hack it
module OpenSSL
  module SSL
    remove_const :VERIFY_PEER
  end
end
OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE

module CVE
  module Status
    class Debian

      def get_url(cve)
        'https://security-tracker.debian.org/tracker/' + cve
      end

      def get_titles(doc)
        doc.search('/html/body/table[1]/tr/td/b').map do |title|
          next unless title.text =~ /^Debian/
          title.text
        end.compact!
      end

      # NOT-FOR-US is indicates this CVE doesn't affect debian
      def skip(doc)
        doc.xpath('/html/body/pre').each do |node|
          return true if node.text =~ /NOT-FOR-US/
        end
        false
      end

      def output(status)
      end

      def status(cve)
        errata_data = Hash.new

        begin
          open(get_url(cve)) do |content|
            doc = Nokogiri::HTML(content.read)

            return if skip(doc)

            # Grab element titles (from left hand column this time)
            titles = get_titles(doc)

            # Extract data:
            doc.xpath('/html/body/table[1]/tr').each do |row|
              dist = row.search('td[1]/b').text
              next unless titles.include? dist

              row.xpath('td[2]').each do |data|
                errata_data[dist] = data.text
              end
            end
          end
        rescue OpenURI::HTTPError
          $stderr.puts 'Caught HTTP error. Probably a 404 (not vulnerable)'
          return
        end

        errata_data
      end

      def output(status)

        interesting_platforms = {
          'Debian/stable' => 'Debian 7 (wheezy)',
          'Debian/oldstable' => 'Debian 6 (squeeze)',
        }

        info = {}
        status.each do |name, value|
          interesting_platforms.each do |platform, pretty_name|
            next unless name =~ Regexp.new(platform)
            info[pretty_name] = { 'original_status' => value }
            info[pretty_name]['status'] = value =~ /not vulnerable/ ? 'fixed' : 'vulnerable'; 

          end
        end
       info 
      end

    end
  end
end

