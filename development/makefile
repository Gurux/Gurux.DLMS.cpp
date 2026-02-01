#
# --------------------------------------------------------------------------
#  Gurux Ltd
#
#
#
# Filename:        $HeadURL$
#
# Version:         $Revision$,
#                  $Date$
#                  $Author$
#
# Copyright (c) Gurux Ltd
#
#---------------------------------------------------------------------------
#
#  DESCRIPTION
#
# This file is a part of Gurux Device Framework.
#
# Gurux Device Framework is Open Source software; you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; version 2 of the License.
# Gurux Device Framework is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# More information of Gurux products: http://www.gurux.org
#
# This code is licensed under the GNU General Public License v2.
# Full text may be retrieved at http://www.gnu.org/licenses/gpl-2.0.txt
#---------------------------------------------------------------------------
# Generate STATIC library.
TARGET   = libgurux_dlms_cpp.a
CC       = g++
# compiling flags here
CFLAGS   = -O3 -Wall -fPIC 

LINKER   = ar rvs

# linking flags here
LFLAGS   =  

# change these to set the proper directories where each files should be

SRCDIR   = src
OBJDIR   = obj
LIBDIR   = lib

SOURCES  := $(wildcard $(SRCDIR)/*.cpp)
INCLUDES := $(wildcard $(SRCDIR)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
rm       = rm -rf
mkdir    = mkdir -p

$(LIBDIR)/$(TARGET): $(OBJECTS)
	@$(mkdir) $(LIBDIR)
	@$(LINKER) $@ $(LFLAGS) $(OBJECTS)
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
	@$(rm) $(LIBDIR)
	@echo "Executable removed!"
