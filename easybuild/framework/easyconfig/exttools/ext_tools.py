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
Easyconfig module that provides tools for extensions for EasyBuild easyconfigs.

Authors:

* Victor Machado (Do IT Now)
* Danilo Gonzalez (Do IT Now)
"""

from easybuild.framework.easyblock import get_easyblock_instance
from easybuild.framework.easyconfig.exttools.extensions.r_extension import RExtension
from easybuild.framework.easyconfig.templates import TEMPLATE_CONSTANTS
from easybuild.framework.extension import Extension
from easybuild.tools.build_log import EasyBuildError


class ExtTools():
    """Class for extension tools"""

    def __init__(self, ec):
        """
        Initialize the extension tools.

        :param ec: EasyConfig instance
        """

        self.ec = ec

        self.eb = get_easyblock_instance(self.ec)
        self.eb.init_ext_instances()
        self.exts_instances = self.eb.ext_instances

        self.exts_list = self.ec.get('ec', {}).get('exts_list', [])
        self.exts_list_updated = []

    def _get_extension_class(self, ext: Extension):

        # init variables
        ext_class = None

        # get the source urls from the extension instance
        source_urls = ext.options.get('source_urls', [])

        # Remove the trailing '/' if present
        source_urls = [url.rstrip('/') for url in source_urls]

        # get the source name from the source url
        source_name = None
        for url in source_urls:
            for item in TEMPLATE_CONSTANTS:
                if item[1] == url:
                    source_name = item[0]
                    break

        # get the extension class
        if source_name and 'CRAN' in source_name:
            ext_class = 'RPackage'
        else:
            ext_class = self.ec.get('ec', {}).get('exts_defaultclass')

        return ext_class


    def _get_exttools_ext_instance(self, ext: Extension):
        """
        Create an exttools instance of the given extension instance.

        :param ext: the Extension instance to create the exttools ext instance from

        :return: exttools ext instance
        """

        if not ext:
            raise EasyBuildError("Extension not provided to create the extension instance")

        # get the extension class
        ext_class = self._get_extension_class(ext)

        # return the extension instance
        if ext_class == 'RPackage':
            return RExtension(ext)
        else:
            raise EasyBuildError("extension class %s not supported" % ext_class)

    def update_exts_list(self):
        """
        Update the extension list.
        """

        # init variables
        latest_dict = {}
        self.exts_list_updated = []

        # get the latest versions of the extensions
        for ext_instance in self.exts_instances:

            # if the extension instance was just a string, add it to the updated list and continue
            if not ext_instance.version and not ext_instance.options:
                continue

            # get the exttools extension instance
            ext = self._get_exttools_ext_instance(ext_instance)

            # get the latest version of the extension
            name, version, checksum = ext.get_update()

            # add the latest version to the a dictionary for a quick lookup
            if name and version and checksum:
                latest_dict[name.lower()] = {'name': name, 'version': version, 'checksum': checksum}

        # keep the order and options of the extensions and update the list
        for ext in self.exts_list:

            # if the extension is a string, just add it to the updated list
            if isinstance(ext, str):
                self.exts_list_updated.append(ext)
                continue

            # get the extension name
            ext_name = ext[0].lower()
            ext_version = ext[1]
            ext_options = ext[2]

            # if there is an updated version of the extension, add it to the updated list
            if ext_name in latest_dict:

                # get updated values
                latest = latest_dict[ext_name]

                name = latest['name']
                version = latest['version']
                options = ext_options.copy()
                options['checksums'] = latest['checksum']

                # add the updated extension to the list
                self.exts_list_updated.append((name, version, options))
            else:
                self.exts_list_updated.append(ext)
