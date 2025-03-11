# project name (generate executable with this name)
TARGET   = gurux.dlms.server.bin

CC       = g++

# compiling flags here
CFLAGS   = -c

LINKER   = g++ -o

# linking flags here
LFLAGS   = -L../development/lib

# change these to set the proper directories where each files should be

SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin

SOURCES  := $(wildcard $(SRCDIR)/*.cpp)
INCLUDES := $(wildcard $(SRCDIR)/*.h)

OBJECTS  := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
rm       = rm -rf
mkdir    = mkdir -p

$(BINDIR)/$(TARGET): $(OBJECTS)
	@$(mkdir) $(BINDIR)
	@$(LINKER) $@ $(LFLAGS) $(OBJECTS) -lgurux_dlms_cpp -lpthread
	@echo "Linking complete!"

$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.cpp
	@$(mkdir) $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "Compiled "$<" successfully!"

.PHONEY: clean
clean:
	@$(rm) $(OBJDIR)
	@echo "Cleanup complete!" 
	@echo $(OBJECTS)

.PHONEY: remove
remove: clean
	@$(rm) $(BINDIR)
	@echo "Executable removed!"
