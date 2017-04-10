all: zip

zip:
	zip -r hunganhu.hu_hunganhu@yahoo.com_2017.04.10.zip src README lib

clean:
	rm -f *.zip *~
