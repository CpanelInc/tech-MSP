PROJECT=msp.pl
SHELL=/bin/sh
PERL_BIN=$(shell readlink /usr/local/cpanel/3rdparty/bin/perl)
PERL_BIN_BASE=$(shell dirname $(PERL_BIN))
PATH=$(PERL_BIN_BASE):/usr/local/cpanel/3rdparty/bin:/sbin:/bin:/usr/sbin:/usr/bin
PERLCRITIC=$(PERL_BIN_BASE)/perlcritic
PERLCRITICRC=tools/.perlcriticrc
PERLTIDY=$(PERL_BIN_BASE)/perltidy
PERLTIDYRC=tools/.perltidyrc
PERLTIDYRC_MINIFY=tools/.perltidyrc.minify
NEW_VER=$(shell grep 'our $$VERSION' $(PROJECT) | awk '{print $$4}' | sed -e "s/'//g" -e 's/;//')

.DEFAULT: help
.IGNORE: clean
.PHONY: clean commit final help test tidy
.PRECIOUS: $(PROJECT)
.SILENT: commit final help $(PROJECT).tdy test tidy

# A line beginning with a double hash mark is used to provide help text for the target that follows it when running 'make help' or 'make'.  The help target must be first.
# "Invisible" targets should not be marked with help text.

## Show this help
help:
	printf "\nAvailable targets:\n"
	awk '/^[a-zA-Z\-\_0-9]+:/ { \
		helpMessage = match(lastLine, /^## (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 3, RLENGTH); \
			printf "%-15s - %s\n", helpCommand, helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)
	printf "\n"

## Clean up
clean:
	$(RM) $(PROJECT).tdy

## Commit an intermediate change
commit: tidy
ifndef COMMITMSG
	echo 'COMMITMSG is undefined.  Add COMMITMSG="My commit description" to make command line.' && exit 2
endif
	git add $(PROJECT)
	git commit -m "$(COMMITMSG)"

## Make final commit
final:
	git add $(PROJECT)
	git commit -m "$(PROJECT) $(NEW_VER)"
	echo 'Ready to git push to origin!'

$(PROJECT).tdy: $(PROJECT)
	which $(PERLTIDY) | egrep -q '/usr/local/cpanel' || echo "cPanel perltidy not found!  Are you running this on a WHM 64+ system?"
	echo "-- Running tidy"
	$(PERLTIDY) --profile=$(PERLTIDYRC) $(PROJECT)

## Run basic tests
test:
	[ -e /usr/local/cpanel/version ] || ( echo "You're not running this on a WHM system."; exit 2 )
	echo "-- Running perl syntax check"
	perl -c $(PROJECT) || ( echo "$(PROJECT) perl syntax check failed"; exit 2 )
	echo "-- Running perlcritic"
	$(PERLCRITIC) --profile $(PERLCRITICRC) $(PROJECT)

## Run perltidy, compare, and ask for overwrite
tidy: test $(PROJECT).tdy
	echo "-- Checking if tidy"
	if ( diff -u $(PROJECT) $(PROJECT).tdy > /dev/null ); then \
		echo "$(PROJECT) is tidy."; \
		exit 0; \
	else \
		diff -u $(PROJECT) $(PROJECT).tdy | less -F; \
		cp -i $(PROJECT).tdy $(PROJECT); \
		if ( diff -u $(PROJECT) $(PROJECT).tdy > /dev/null ); then \
			echo "$(PROJECT) is tidy."; \
			exit 0; \
		else \
			echo "$(PROJECT) is NOT tidy."; \
			exit 2; \
		fi; \
	fi;

## Create minified file
$(PROJECT).min: test
	echo "-- Running tidy minify"
	$(PERLTIDY) --profile=$(PERLTIDYRC_MINIFY) $(PROJECT) -o $(PROJECT).min
