althttpd:	althttpd.c
	cc -Os -Wall -Wextra -o althttpd althttpd.c

clean:	
	rm -f althttpd
