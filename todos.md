read all of this on paper. and physically plan it out.

research architecture more. potential for some RL work. the biggest thing is signal/noise. but first MVP + initial architecture that's extensible.
- is it going to be a continuous cache on one end of the CVE incidents + pointers for where to look out for and greps and other end is an agent
- how are we giving the agent context?
-- memory? remove repeated issues
- dashboard vs CLI. CLI seems better. Give extensive docs so LLMs can do it too. have it run in CI.
- how are these incidents actually resolved? What's the flow that the people want? 
-- potentially integrate with themis. Similar concept - lots of low signal events. Low Signal channel. Make this extremely high signal channel
-- add themis to this. merge them.
- biggest todo is get deep into how real people use this then build up the agent from that. have an instance go and research this.

- consider sentinel or themis. Themis is better because I can own the SEO.
- plan tweet storm. Worst week in security. See Sarah Guo tweet.

security issues & regulatory diffs. Work on security first, then regulation (which is boring + skippable). Figure out a good one liner.

Security hates tools that are too noisy.

- also make it a long-running dashboard. like eventually you can also have an auth'd version of themis. Get a good dashboard.
- think about each component separately. need to know which service gets their credentials + compute where. 

Using source code, sentinel finds attack vectors then actually attacks on a dummy website version. Also attacks normally. Starts a side instance. Probably need to learn how cybersecurity is done then how to hack (do a CTF) and then how to automate it

Decide what's done in CI, what's done locally. What the dashboard looks like.