# Copyright 2024 Ghent University
#
# This file is part of EasyBuild,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://www.vscentrum.be),
# Flemish Research Foundation (FWO) (http://www.fwo.be/en)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# https://github.com/easybuilders/easybuild
#
# EasyBuild is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# EasyBuild is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with EasyBuild.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Base extension class for EasyBuild EasyConfig extension tools.

Authors:

* Victor Machado (Do IT Now)
* Danilo Gonzalez (Do IT Now)
"""

from easybuild.framework.extension import Extension


class BaseExtension:
    """
    Base extension class for EasyBuild EasyConfig extension tools.
    """

    def __init__(self, ext: Extension):
        self.ext = ext

    @property
    def name(self):
        """
        Get the name of the package extension.
        """
        return self.ext.name

    @property
    def version(self):
        """
        Get the version of the package extension.
        """
        return self.ext.version

    def get_update(self):
        """
        Get the latest name, version and checksum of the extension
        """
        raise NotImplementedError("Subclasses should implement this!")
