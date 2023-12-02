CC = gcc  # compiler
CFLAGS = -Wall -Wno-maybe-uninitialized
LDFLAGS = -lpcap
OBJFILES = pcap_ex.o
TARGET = pcap_ex

all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)
	# Remove the object file after linking
	rm -f $(OBJFILES)

clean:
	rm -rf $(OBJFILES) $(TARGET)
