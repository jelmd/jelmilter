# jelmilter

jelmilter uses [milter4j](https://github.com/jelmd/milter4j) to implement several mail filters:

- **HeloCheck**: A MailFilter that verifies the connection endpoint
  (mail server / MTA) against the submitted [E]HLO parameters.

- **RegexCheck**: A MailFilter that checks emails against
  [regular expressions](https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html) or for the presence of specific strings.

- **WhoisCheck**: A MailFilter that extracts URLs from an email and checks the
  corresponding WHOIS records of the related site using a whois-spam server.
  Since more and more domain owners and registries now hide ownership
  information, this filter is no longer very useful in practice. However, it
  still serves as a good example of how to implement custom MailFilters.

