require 'nokogiri'
require 'open-uri'

module CVE
  module Status
    class RHEL

      def get_url(cve)
        'https://access.redhat.com/security/cve/' + cve
      end

      def get_titles(table)
        @titles = table.css('th').map do |title|
          title.text
        end
      end

      # This should be a statement on vulnerability.
      # Not sure how robust this is though
      def skip(doc)
        doc.xpath('//*[@id="content"]/div/p[4]').each do |node|
          if node.text =~ /Not vulnerable/
            $stderr.puts 'Not vulnerable' # todo: add debugging?
            return true 
          end
        end
        return
      end

      def status(cve)
        errata_data = Array.new

        begin
          open(get_url(cve)) do |content|
            doc = Nokogiri::HTML(content.read)

            return if skip(doc)

            doc.css('.docstable').each do |table|

              # Extract table headers:
              get_titles(table)

              # Extract data:
              table.css('tr').each do |row|
                row_info = Hash.new

                row.css('td').each_with_index do |data, index|
                  row_info[@titles[index]] = data.text
                end

                errata_data.push(row_info) unless row_info.empty?
              end
            end
          end
        rescue RuntimeError
          # If this happens, RHEL is probably not vulnerable
          $stderr.puts 'Caught runtime error, probably a broken redirect (not vulnerable)'
          return
        end
        errata_data
      end

      # output a table of status
      # i.e RHEL 5 => { errata => RHSA-210020202, package => 'foo', date => '20130612', status => 'fixed' }
      def output(status)

        # Todo: abstract this out
        interesting_platforms = {
          'Red Hat Enterprise Linux version 5 \((\w+)\)' => 'RHEL 5',
          'Red Hat Enterprise Linux version 6 \((\w+)\)'=> 'RHEL 6',
        }

        mapping = {
          'Release Date' => { :name => 'date', :parser => Proc.new { |d| Date.parse(d) } },
          'Errata'       => { :name => 'errata', :implies => { 'status' => 'fixed' }, },
        }

        info = Hash.new
        status.map do |entry|
          next unless entry['Platform']

          # Filter data so we only return interesting stuff
          interesting_platforms.each do |platform, pretty_name|
            next unless entry['Platform'] =~ Regexp.new(platform)
            info[pretty_name] = {}
            # TODO: do I need a not vulnerable flag?
            mapping.each do |orig, new|
              info[pretty_name][new[:name]] = new[:parser] ? new[:parser].call(entry[orig]) : entry[orig]
              new.fetch(:implies, {}).each do |implication, content|
                info[pretty_name][implication] = content
              end
            end
          end
        end
        info
      end
    end
  end
end
