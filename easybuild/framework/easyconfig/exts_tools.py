# #
# Copyright 2009-2024 Ghent University
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
# #

"""
Easyconfig module that provides tools for extensions for EasyBuild easyconfigs.

Authors:

* Victor Machado (Do IT Now)
* Danilo Gonzalez (Do IT Now)
"""

import hashlib
import re
import requests

from easybuild.base import fancylogger
from easybuild.framework.easyblock import EasyBlock, get_easyblock_instance
from easybuild.framework.easyconfig.easyconfig import process_easyconfig
from easybuild.tools.build_log import EasyBuildError
from easybuild.tools.build_log import print_error, print_msg, print_warning
from easybuild.tools.config import build_option, update_build_option
from easybuild.tools.filetools import back_up_file, write_file, read_file
from easybuild.tools.robot import search_easyconfigs
from easybuild.tools.utilities import INDENT_4SPACES

# URLs for package repositories
CRANDB_URL = "https://crandb.r-pkg.org"
CRANDB_CONTRIB_URL = "https://cran.r-project.org/src/contrib"
PYPI_URL = "https://pypi.org/pypi"
BIOCONDUCTOR_URL = "https://bioconductor.org/packages"
BIOCONDUCTOR_PKGS_URL = "bioc/packages.json"
BIOCONDUCTOR_ANNOTATION_URL = "data/annotation/packages.json"
BIOCONDUCTOR_EXPERIMENT_URL = "data/experiment/packages.json"

# offsets for printing the package information
PKG_NAME_OFFSET = 20
PKG_VERSION_OFFSET = 10
CHECKSUM_OFFSET = 20
INFO_OFFSET = 20

# List of packages to exclude from the dependencies
EXCLUDE_R_LIST = ['R', 'base', 'compiler', 'datasets', 'graphics',
                  'grDevices', 'grid', 'methods', 'parallel',
                  'splines', 'stats', 'stats4', 'tcltk', 'tools',
                  'utils', 'MASS']

# Global variable to store Bioconductor packages
bioc_packages_cache = None

# Logger
_log = fancylogger.getLogger('easyblock')


def _get_R_pkg_checksum(pkg_metadata, bioconductor_version=None):
    """
    Get the checksum of the given R package version

    :param pkg_metadata: package metadata
    :param bioconductor_version: bioconductor version to use (if any)

    :return: checksum of the given R package version
    """

    if not pkg_metadata:
        raise EasyBuildError("No R package metadata provided to get the checksum")

    # check if checksum is provided in the metadata
    checksum = pkg_metadata.get('MD5sum', '')

    # if checksum is not provided, calculate it
    if not checksum:
        # get package information
        pkg_name = pkg_metadata.get('Package', '')
        pkg_version = pkg_metadata.get('Version', '')

        # download package from the database
        package = _get_pkg('RPackage', pkg_name, pkg_version, bioconductor_version)

        # calculate the checksum
        if package:
            checksum = hashlib.md5(package).hexdigest()
        else:
            print_warning("Failed to download package %s v%s to calculate the checksum" %
                          (pkg_name, pkg_version), log=_log)
            checksum = ''

    return checksum


def _get_python_pkg_checksum(pkg_metadata):
    """
    Get the checksum of the given Python package version

    :param pkg_metadata: package metadata

    :return: checksum of the given Python package version
    """

    if not pkg_metadata:
        raise EasyBuildError("No python package metadata provided to get the checksum")

    # initialize variable
    checksum = ''

    # get the data of the given package version
    pkg_name = pkg_metadata.get('info', {}).get('name', '')
    pkg_version = pkg_metadata.get('info', {}).get('version', '')
    pkg_releases = pkg_metadata.get('releases', {})
    pkg_info = pkg_releases.get(pkg_version, [])

    # parse the version info to get the checksum
    if pkg_info:
        # look for sdist first
        for file_info in pkg_info:
            if file_info.get('packagetype') == 'sdist':
                checksum = file_info.get('digests', {}).get('sha256', '')

        # if no sdist found, take the checksum of the first distribution file
        if not checksum:
            checksum = pkg_info[0].get('digests', {}).get('sha256', '')

        if not checksum:
            print_warning("Failed to get package %s v%s checksum from distribution file" %
                          (pkg_name, pkg_version), log=_log)
    else:
        print_warning("Failed to get package %s v%s information to grasp the checksum" %
                      (pkg_name, pkg_version), log=_log)

    return checksum


def _get_bioconductor_pkgs_metadata(bioc_version):
    """
    Get the list of Bioconductor packages from the Bioconductor database.

    :param bioc_version: Bioconductor version

    :return: list of Bioconductor packages
    """

    if not bioc_version:
        raise EasyBuildError("No bioconductor version provided to get the bioconductor packages")

    # global variable to store the bioconductor packages
    global bioc_packages_cache

    # bioconductor URLs
    bioc_urls = ['%s/json/%s/%s' % (BIOCONDUCTOR_URL, bioc_version, BIOCONDUCTOR_PKGS_URL),
                 '%s/json/%s/%s' % (BIOCONDUCTOR_URL, bioc_version, BIOCONDUCTOR_ANNOTATION_URL),
                 '%s/json/%s/%s' % (BIOCONDUCTOR_URL, bioc_version, BIOCONDUCTOR_EXPERIMENT_URL)]

    # check if the packages are already stored in memory
    if bioc_packages_cache is None:

        # initialize the cache
        bioc_packages_cache = {}

        # retrieve packages from the cloud
        for url in bioc_urls:
            try:
                response = requests.get(url)

                if response.status_code == 200:
                    bioc_packages_cache.update(response.json())
                else:
                    print_warning(
                        f"Failed to get biocondcutor packages from {url}: HTTP status: {response.status_code}")
            except Exception as err:
                print_warning(f"Exception while getting bioconductor packages from  {url}: {err}")

    return bioc_packages_cache


def _get_pkg(pkg_class, pkg_name, pkg_version, bioconductor_version=None):
    """
    Get the package from the database

    : param pkg_class: package class (RPackage)
    : param pkg_name: package name
    : param pkg_version: package version
    : param bioconductor_version: bioconductor version (if any)

    : return: package from database
    """

    if not pkg_class:
        raise EasyBuildError("No package class provided to get the package")

    if not pkg_name:
        raise EasyBuildError("No package name provided to get the package")

    if not pkg_version:
        raise EasyBuildError("No package version provided to get the package")

    # initialize variables
    urls = []
    pkg = None

    # build the url to get the package from the database
    if pkg_class == "RPackage":
        # URL for CRANDB
        crandb_url = "%s/%s_%s.tar.gz" % (CRANDB_CONTRIB_URL, pkg_name, pkg_version)
        urls.append(crandb_url)

        # URL for CRANDB Archive
        crandb_archive_url = "%s/Archive/%s/%s_%s.tar.gz" % (CRANDB_CONTRIB_URL, pkg_name, pkg_name, pkg_version)
        urls.append(crandb_archive_url)

        # URL for Bioconductor package
        if bioconductor_version:
            # Construct the URL for Bioconductor package
            url = "%s/%s/bioc/src/contrib/%s_%s.tar.gz" % (BIOCONDUCTOR_URL,
                                                           bioconductor_version, pkg_name, pkg_version)
            urls.append(url)
    else:
        raise EasyBuildError("get_pkg function only supports RPackage extensions")

    try:
        for url in urls:
            # get the package's metadata from the database
            response = requests.get(url, stream=True)

            if response.status_code == 200:
                pkg = response.content
                break

    except Exception as err:
        print_warning("Exception while downloading package %s v%s. Error: %s" % (pkg_name, pkg_version, err))

    return pkg


def _get_pkg_metadata(pkg_class, pkg_name, pkg_version=None, bioc_version=None):
    """
    Get the metadata of the given package

    :param pkg_class: package class (RPackage, PythonPackage)
    :param pkg_name: package name
    :param pkg_version: package version. If None, the latest version will be retrieved.
    :param bioc_version: bioconductor version (if any)

    :return: package metadata
    """

    # initialize variables
    pkg_metadata = None
    bioc_packages = None

    if not pkg_name:
        raise EasyBuildError("No package name provided to get the package metadata")

    # build the url to get the metadata from the database
    if pkg_class == "RPackage":
        if pkg_version:
            url = "%s/%s/%s" % (CRANDB_URL, pkg_name, pkg_version)
        else:
            url = "%s/%s" % (CRANDB_URL, pkg_name)

        # get bioc packages if bioconductor version is provided
        if bioc_version:
            bioc_packages = _get_bioconductor_pkgs_metadata(bioc_version)

    elif pkg_class == "PythonPackage":
        url = "%s/%s/json" % (PYPI_URL, pkg_name)

    else:
        raise EasyBuildError("exts_defaultclass %s not supported" % pkg_class)

    try:
        # get the package's metadata from the database
        response = requests.get(url)

        if response.status_code == 200:
            pkg_metadata = response.json()

    except Exception as err:
        print_warning("Exception while getting metadata for extension %s: %s" % (pkg_name, err))

    # if the package is not found in the database, then iterate over bioconductor packages to find the package
    if not pkg_metadata and bioc_packages:
        for package in bioc_packages.items():
            if package[0] == pkg_name:
                pkg_metadata = package[1]
                break

    return pkg_metadata


def _format_metadata_as_extension(pkg_class, pkg_metadata, bioconductor_version=None):
    """
    Get the package metadata as an exts_list extension format

    :param pkg_class: package class (RPackage, PythonPackage, PerlPackage)
    :param pkg_metadata: package metadata
    :param bioconductor_version: bioconductor version

    :return: package metadata in exts_list extension format
    """

    if not pkg_metadata:
        raise EasyBuildError("No package metadata provided to format as extension")

    # check the package class and parse the metadata accordingly
    if pkg_class == "RPackage":
        name = pkg_metadata.get('Package', '')
        version = pkg_metadata.get('Version', '')
        checksum = _get_R_pkg_checksum(pkg_metadata, bioconductor_version)

    elif pkg_class == "PythonPackage":
        name = pkg_metadata.get('info', {}).get('name', '')
        version = pkg_metadata.get('info', {}).get('version', '')
        checksum = _get_python_pkg_checksum(pkg_metadata)

    else:
        raise EasyBuildError("exts_defaultclass %s not supported" % pkg_class)

    # remove any non-alphanumeric characters from the version
    allowed_version_chars = r'[^0-9><=!*. \-]'
    version = re.sub(allowed_version_chars, '', version)

    # remove any new line characters
    name = name.replace('\n', '')
    version = version.replace('\n', '')
    checksum = checksum.replace('\n', '')

    return {"name": name, "version": version,  "options": {"checksums": [checksum]}}


def _get_clean_pkg_values(pkg_name=None, pkg_version=None, pkg_options=None):
    """
    Clean the given extension values

    :param pkg_name: package name to clean
    :param pkg_version: package version to clean
    :param pkg_options: package options to clean
    """

    clean_name, clean_version, clean_options = pkg_name, pkg_version, pkg_options

    # clean the name
    if pkg_name:
        # Regular expression pattern to match versions like 'RSQLite (>= 2.0)'
        pattern = r'^(?P<name>[^\s]+) \((?P<info>.+)\)$'
        match = re.match(pattern, pkg_name)

        # check if there is a match
        if match:
            clean_name = match.group('name')
            pkg_version = match.group('info')

        # remove any new line characters from the name
        clean_name = clean_name.replace('\n', '')

    # clean the version
    if pkg_version:
        # allow only alphanumeric characters in the version
        allowed_version_chars = r'[^0-9><=!*. \-]'

        # remove any non-alphanumeric characters from the version
        clean_version = re.sub(allowed_version_chars, '', pkg_version)

        # remove any new line characters from the version
        clean_version = clean_version.replace('\n', '')

    # clean the options
    if pkg_options:
        checksum = pkg_options['checksums']
        if checksum:
            clean_options = {}
            clean_options['checksums'] = [checksum[0].replace('\n', '')]

    return clean_name, clean_version, clean_options


def _get_R_extension_dependencies(extension, bioconductor_version=None, exts_list=[], installed_exts=[], processed_exts=[]):
    """
    Process the dependencies of the given R extension.

    :param extension: the extension to get dependencies from
    :param bioconductor_version: bioconductor's version to use (if any)
    :param exts_list: list of extensions of the current EasyConfig (if any)
    :param installed_exts: list of installed extensions by dependencies (if any)
    :param processed_exts: list of extensions already processed

    :return: list of dependencies of the given R extension
    """

    # check if the extension is empty
    if not extension:
        raise EasyBuildError("No extension provided to get the dependencies from")

    # init variables
    dependencies = []

    # get the values of the extension
    ext_name, ext_version, _ = _get_extension_values(extension)

    # if the extension is a string, then skip further processing
    if isinstance(extension, str):
        return []

    # get metadata of the version of the extension
    metadata = _get_pkg_metadata("RPackage", ext_name, ext_version, bioconductor_version)

    # get the dependencies of the extension
    if metadata:
        metadata_dependencies = []

        for key in ('Depends', 'Imports', 'LinkingTo'):
            if key in metadata:
                if isinstance(metadata[key], list):
                    for item in metadata[key]:
                        metadata_dependencies.append(item)
                elif isinstance(metadata[key], dict):
                    for pkg_name, _ in metadata[key].items():
                        metadata_dependencies.append(pkg_name)

        for dep_name in metadata_dependencies:

            # clean the dependency values
            dep_name, _, _ = _get_clean_pkg_values(dep_name)

            # check if the dependency already processed
            is_processed = False
            for proc_ext in processed_exts:
                if proc_ext.lower() == dep_name.lower():
                    is_processed = True
                    break

            # if the dependency is already processed, then skip
            if is_processed:
                continue

            # append the extension to the list of processed extensions
            processed_exts.append(dep_name)

            # check if the dependency is already in the exts_list
            is_in_exts_list = False
            for ext in exts_list:
                if ext[0].lower() == dep_name.lower():
                    is_in_exts_list = True
                    print_msg(
                        f"\t{dep_name:<{PKG_NAME_OFFSET}} is in the original exts_list. RECOMMENDATION: Consider removing {dep_name} from the original exts_list", prefix=False, log=_log)
                    break

            # if the dependency is in the exts_list, then skip
            if is_in_exts_list:
                continue

            # check if the dependency is in the exclude list
            is_excluded = False
            for exclude_ext in EXCLUDE_R_LIST:
                if exclude_ext.lower() == dep_name.lower():
                    is_excluded = True
                    print_msg(f"\t{dep_name:<{PKG_NAME_OFFSET}} is blacklisted", prefix=False, log=_log)
                    continue

            # if the dependency is excluded, then skip
            if is_excluded:
                continue

            # check if the dependency is already installed by a dependency
            is_installed = False
            for inst_ext in installed_exts:
                inst_ext_name, _, inst_ext_options = _get_extension_values(inst_ext)
                if inst_ext_name.lower() == dep_name.lower():
                    is_installed = True
                    print_msg(
                        f"\t{dep_name:<{PKG_NAME_OFFSET}} installed by dependency: {inst_ext_options['easyconfig_path']}", prefix=False, log=_log)
                    break

            # if the dependency is already installed, then skip
            if is_installed:
                continue

            print_msg(f"\t{dep_name:<{PKG_NAME_OFFSET}} added as dependency", prefix=False, log=_log)

            # build the metadata dependency as extension getting the last version
            dep_name = {'name': dep_name, 'version': None, 'options': {}}

            # recursively get dependencies of dependency
            deps = _get_R_extension_dependencies(dep_name,
                                                 bioconductor_version,
                                                 exts_list,
                                                 installed_exts,
                                                 processed_exts)

            # append the dependencies to the list
            dependencies.extend(deps)

            # append the dependency to the list
            dependencies.append(dep_name)

    return dependencies


def _print_extension(extension):
    """
    Print the list of extensions in a pretty format.

    :param exts_list: list of extensions to print
    """

    if not extension:
        raise EasyBuildError("No extension provided to print")

    # get the values of the extension
    ext_name, ext_version, ext_options = _get_extension_values(extension)

    name = ext_name
    version = ('_' if ext_version is None else ext_version)
    checksum = ext_options.get('checksums', None)
    if checksum:
        checksum = checksum[0]

    # print the extension
    print_msg(
        f"\t{name:<{PKG_NAME_OFFSET}} v{version:<{PKG_VERSION_OFFSET}} checksum: {checksum:<{CHECKSUM_OFFSET}}", prefix=False, log=_log)


def _get_completed_R_exts_list(exts_list, bioconductor_version=None, installed_exts=[]):
    """
    Complete the R extensions list with its dependencies in correct order.

    :param exts_list: list of extensions to be updated.
    :param bioconductor_version: bioconductor's version to use (if any)
    :param installed_exts: list of installed extensions by dependencies (if any)

    :return: list of extensions for a complete exts_list
    """

    # check if the exts_list is empty
    if not exts_list:
        raise EasyBuildError("No exts_list provided for completing")

    # get the dependendy tree. i.e. list of dependencies for each extension
    completed_exts_list = []
    for ext in exts_list:

        # get the values of the extension
        ext_name, ext_version, ext_options = _get_extension_values(ext)

        print()
        print_msg("Dependencies of '%s':" % ext_name, prefix=False, log=_log)

        # get dependencies of the extension
        dependencies = _get_R_extension_dependencies(ext, bioconductor_version, exts_list, installed_exts)

        # store the dependencies in the complete list
        completed_exts_list.extend(dependencies)

        # store the extension in the complete list
        completed_exts_list.append({"name": ext_name, "version": ext_version, "options": ext_options})

    # there could be some duplicates in the dependency tree, so we need to clean them
    print()
    print_msg("Deleting duplicates...", log=_log)

    completed_cleaned_exts_list = []
    for ext in completed_exts_list:
        # get the values of the extension
        ext_name, ext_version, ext_options = _get_extension_values(ext)

        # check if the extension is already in the cleaned list
        is_in_cleaned_list = False
        for cleaned_ext in completed_cleaned_exts_list:
            cleaned_ext_name, _, _ = _get_extension_values(cleaned_ext)
            if cleaned_ext_name.lower() == ext_name.lower():
                is_in_cleaned_list = True
                break

        # if the extension is not in the cleaned list, then append it
        if is_in_cleaned_list:
            continue

        # append the extension to the cleaned list
        completed_cleaned_exts_list.append(ext)

    print_msg("Fulfilling exts_list...", log=_log)

    # go over the dependency tree and fill the version and checksums
    complete_cleaned_fulfilled_exts_list = []
    for ext in completed_cleaned_exts_list:

        # get the values of the extension
        ext_name, ext_version, ext_options = _get_extension_values(ext)

        # get metadata of the extension
        metadata = _get_pkg_metadata(pkg_class="RPackage",
                                     pkg_name=ext_name,
                                     pkg_version=ext_version,
                                     bioc_version=bioconductor_version)

        # process the metadata, format it as an extension, and store it
        if metadata:
            ext = _format_metadata_as_extension("RPackage", metadata, bioconductor_version)
            complete_cleaned_fulfilled_exts_list.append(ext)
            _print_extension(ext)

    # return the complete list of extensions
    return complete_cleaned_fulfilled_exts_list


def _get_completed_exts_list(exts_list, exts_defaultclass, installed_exts, bioconductor_version=None):
    """
    Get the completed list of all extensions in exts_list.

    :param exts_list: list of extensions to be updated.
    :param exts_defaultclass: default class for the extensions ('RPackage', 'PythonPackage')
    :param installed_exts: list of installed extensions by depdencies
    :param bioconductor_version: bioconductor's version to use (if any)

    :return: list with extensions updated to their latest versions.
    """

    # init variables
    completed_exts_list = []

    # check if the exts_list is empty
    if not exts_list:
        raise EasyBuildError("No exts_list provided for completing")

    # check if the exts_defaultclass is empty
    if not exts_defaultclass:
        raise EasyBuildError("No exts_defaultclass provided for completing")

    if exts_defaultclass == "RPackage":
        completed_exts_list = _get_completed_R_exts_list(exts_list, bioconductor_version, installed_exts)
    elif exts_defaultclass == "PythonPackage":
        # _complete_python_exts_list(exts_list, installed_exts)
        raise EasyBuildError("--complete-exts-list not implemented for PythonPackage yet")
    else:
        raise EasyBuildError("exts_defaultclass %s not supported" % exts_defaultclass)

    return completed_exts_list


def _get_updated_exts_list(exts_list, exts_defaultclass, bioconductor_version=None):
    """
    Get the list of all extensions in exts_list updated to their latest version.

    :param exts_defaultclass: default class for the extensions ('RPackage', 'PythonPackage')
    :param exts_list: list of extensions to be updated.
    :param bioconductor_version: bioconductor's version to use (if any)

    :return: list with extensions updated to their latest versions.
    """

    # check if the exts_list is empty
    if not exts_list:
        raise EasyBuildError("No exts_list provided for updating")

    # check if the exts_defaultclass is empty
    if not exts_defaultclass:
        raise EasyBuildError("No exts_defaultclass provided for updating")

    # init variables
    updated_exts_list = []

    # aesthetic terminal print
    print()

    # loop over all extensions and update their version
    for ext in exts_list:

        if isinstance(ext, str):
            # if the extension is a string, then store it as is and skip further processing
            updated_exts_list.append({"name": ext, "version": None,  "options": None})

            # print message to the user
            print_msg(
                f"{ext:<{PKG_NAME_OFFSET}} v{('---'):<{PKG_VERSION_OFFSET}} {'letf as is':<{INFO_OFFSET}}", log=_log)

            continue

        elif isinstance(ext, tuple):
            # get the values of the exts_list extension
            ext_name, ext_version, ext_options = _get_extension_values(ext)

        else:
            raise EasyBuildError("Invalid extension format")

        # get metadata of the latest version of the extension
        metadata = _get_pkg_metadata(pkg_class=exts_defaultclass,
                                     pkg_name=ext_name,
                                     pkg_version=None,
                                     bioc_version=bioconductor_version)

        if metadata:
            # process the metadata and format it as an extension
            updated_ext = _format_metadata_as_extension(exts_defaultclass, metadata, bioconductor_version)

            # print message to the user
            if ext_version == updated_ext['version']:
                print_msg(
                    f"{ext_name:<{PKG_NAME_OFFSET}} v{('_' if ext_version is None else ext_version):<{PKG_VERSION_OFFSET}} {'up-to-date':<{INFO_OFFSET}}", log=_log)
            else:
                print_msg(
                    f"{ext_name:<{PKG_NAME_OFFSET}} v{('_' if ext_version is None else ext_version):<{PKG_VERSION_OFFSET}} updated to v{updated_ext['version']:<{INFO_OFFSET}}", log=_log)

        else:
            # no metadata found, therefore store the original extension
            updated_ext = {"name": ext_name, "version": ext_version,  "options": ext_options}

            # print message to the user
            print_msg(
                f"{ext_name:<{PKG_NAME_OFFSET}} v{('_' if ext_version is None else ext_version):<{PKG_VERSION_OFFSET}} {'info not found':<{INFO_OFFSET}}", log=_log)

        # store the updated extension
        updated_exts_list.append(updated_ext)

    # aesthetic terminal print
    print()

    return updated_exts_list


def _get_updated_easyconfig(ec, update_param, update_data):
    """
    Get a new Easyconfig with the updated given data.

    :param ec: EasyConfig instance to update.
    :param update_param: parameter to update in the EasyConfig.
    :param update_data: data to update in the EasyConfig.

    :return: new EasyConfig instance with the updated data.
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to udpate Easyconfig")

    if not update_param:
        raise EasyBuildError("No parameter provided to update Easyconfig")

    if not update_data:
        raise EasyBuildError("No data provided to update Easyconfig")

    if update_param == "exts_list":
        # format the new exts_list to be written to the easyconfig file
        exts_list_formatted = ['exts_list = [']

        # iterate over the new extensions list and format them
        for ext in update_data:

            if ext['version'] is None:
                exts_list_formatted.append("%s'%s'," % (INDENT_4SPACES, ext['name']))
            else:
                # append name and version
                exts_list_formatted.append("%s('%s', '%s', {" % (INDENT_4SPACES, ext['name'], ext['version']))

                # iterate over the options and format them
                for key, value in ext['options'].items():
                    # if value is a string, then add quotes so they are printed correctly
                    if isinstance(value, str):
                        value = "'%s'" % value

                    # append the key and value of the option
                    exts_list_formatted.append("%s'%s': %s," % (INDENT_4SPACES * 2, key, value))

                # close the extension
                exts_list_formatted.append('%s}),' % (INDENT_4SPACES,))

        # close the exts_list
        exts_list_formatted.append(']\n')

        # read the easyconfig file and replace the exts_list with the new one
        regex = re.compile(r'^exts_list(.|\n)*?\n\]\s*$', re.M)
        new_ec = regex.sub('\n'.join(exts_list_formatted), read_file(ec['spec']))
    else:
        raise EasyBuildError("Invalid parameter to update Easyconfig")

    return new_ec


def _get_dependencies(ec):
    """
    Get the dependencies from an EasyConfig instance.

    :param ec: EasyConfig instance

    :return: list of dependencies from the given EasyConfig instance.
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to get dependencies from")

    app: EasyBlock = get_easyblock_instance(ec)
    return app.cfg.dependencies()


def _get_exts_list(ec):
    """
    Get the extension list from the given EasyConfig instance.

    :param ec: EasyConfig instance.

    :return: list of extensions from the given EasyConfig instance.
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to retrieve extensions from")

    # get the extension list from the easyconfig file
    exts_list = ec.get('ec', {}).get('exts_list', [])

    return exts_list


def _get_exts_list_class(ec):
    """
    Get the exts_defaultclass or deduce it from the given EasyConfig instance.

    :param ec: EasyConfig instance.

    :return: the class of the extensions from the given EasyConfig instance.
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to retrieve extensions from")

    # get the extension list class from the easyconfig file
    exts_list_class = ec.get('ec', {}).get('exts_defaultclass', None)

    # if no exts_defaultclass is found, try to deduce it from the EasyConfig parameters
    if not exts_list_class:

        # get EasyConfig parameters
        name = ec.get('ec', {}).get('name', None)
        easyblock = ec.get('ec', {}).get('easyblock', None)

        # check if we can deduce the extension list class from the EasyConfig parameters
        if name and (name == 'R') or (name.startswith('R-')):
            exts_list_class = 'RPackage'

        if name and (name == 'Python') or (name.startswith('Python-')):
            exts_list_class = 'PythonPackage'

        if easyblock and (easyblock == 'PythonBundle'):
            exts_list_class = 'PythonPackage'

    return exts_list_class


def _get_bioconductor_version(ec):
    """
    Get the Bioconductor version stored in the local_biocver parameter from the given EasyConfig instance.

    :param ec: EasyConfig instance.

    :return: The Bioconductor version of the given EasyConfig instance (if any).
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to retrieve extensions from")

    # get the Bioconductor version from the easyconfig file
    # assume that the Bioconductor version is stored in the 'local_biocver' parameter
    # as this is not a standard parameter we need to parse the raw text
    rawtxt = getattr(ec['ec'], 'rawtxt', '')
    match = re.search(r'local_biocver\s*=\s*([0-9.]+)', rawtxt)

    if match:
        bioconductor_version = match.group(1)
    else:
        bioconductor_version = None

    return bioconductor_version


def _get_extension_values(extension):
    """
    Extract the name, version, and options from an extension.

    :param extension: extension instance
    """
    if isinstance(extension, str):
        return extension, "", {}

    elif isinstance(extension, tuple):
        if len(extension) == 1:
            return extension[0], "", {}
        elif len(extension) == 2:
            return extension[0], extension[1], {}
        elif len(extension) == 3:
            return extension[0], extension[1], extension[2]
        else:
            raise EasyBuildError("Invalid number of elements in extension tuple")

    elif isinstance(extension, dict):
        return (
            extension.get('name', ""),
            extension.get('version', ""),
            extension.get('options', {})
        )

    else:
        raise EasyBuildError("Invalid extension instance")


def _crosscheck_exts_list(exts_list, installed_exts):
    """
    Print the list of extensions that are already installed by a dependency.

    :param exts_list: list of extensions of the current EasyConfig
    :param installed_exts: list of installed extensions
    """

    # init variables
    match = False

    # aesthetic print
    print()

    for ext in exts_list:

        # get the name and version of the exts_list extension
        ext_name, ext_version, _ = _get_extension_values(ext)

        # check if the extension is already installed by a dependency
        for inst_ext in installed_exts:

            # get the name and version of the installed extension
            inst_ext_name, inst_ext_version, inst_ext_options = _get_extension_values(inst_ext)

            # check if the extension is already installed by a dependency
            if inst_ext_name.lower() == ext_name.lower():
                match = True
                print_msg(
                    f"{ext_name:<{PKG_NAME_OFFSET}} v{('_' if ext_version is None else ext_version):<{PKG_VERSION_OFFSET}} {'in exts_list':<{INFO_OFFSET}}", log=_log)
                print_msg(
                    f"{inst_ext_name:<{PKG_NAME_OFFSET}} v{('_' if inst_ext_version is None else inst_ext_version):<{PKG_VERSION_OFFSET}} in dependency {inst_ext_options['easyconfig_path']:<{INFO_OFFSET}}\n", log=_log)

                break

    if not match:
        print_msg("No pre-installed extensions found in the exts_list!\n", log=_log)


def _get_installed_exts(ec, ec_dep=None, processed_deps=[]):
    """
    Generate a list of extensions that will be pre-installed due to dependencies or build_dependencies specified in the easyconfig parameters.

    :param ec: original EasyConfig instance to retrieve extensions from
    :param ec_dep: dependency EasyConfig instance to retrieve extensions from
    :param processed_deps: list of processed dependencies
    """

    if not ec:
        raise EasyBuildError("No EasyConfig instance provided to retrieve extensions from")

    print_msg(f"\r\tDependencies processed: {len(processed_deps)}", newline=False, prefix=False, log=_log)

    # init variable to store the installed extensions
    installed_exts = []

    # if ec_dep is provided, then get the dependencies of the dependency
    # else get dependencies of the original EasyConfig
    if ec_dep:
        dependencies = _get_dependencies(ec_dep)
    else:
        dependencies = _get_dependencies(ec)

    # set terse mode to True to avoid printing unnecessary information
    terse = build_option('terse')
    update_build_option('terse', True)

    # get the extensions of the dependencies of the current EasyConfig
    for dep in dependencies:

        # get dependency's name
        dep_name = dep['full_mod_name'].replace('/', '-') + ".eb"

        # check if dependency was already processed. If so, skip it
        if dep_name in processed_deps:
            continue

        # add dependency to the list of processed dependencies
        processed_deps.append(dep_name)

        # If dependency is a system dependency, store it as an extension being installed and skip futher processing
        if dep['system']:
            installed_exts.extend([{'name': dep['name'], 'version': dep['version']}])
            continue

        # search for the corresponding EasyConfig file
        easyconfigs = search_easyconfigs(dep_name, print_result=False)

        # if easyconfig files were found, then process them
        if easyconfigs:

            # print warning if more than one EasyConfig file was found
            if len(easyconfigs) > 1:
                print_warning("More than one EasyConfig file found for dependency %s: %s", dep_name, easyconfigs)

            # process only the first EasyConfig file found
            easyconfig_dep = process_easyconfig(easyconfigs[0], validate=False)[0]

            # Search recursively for pre-installed extensions of dependencies of the current EasyConfig
            installed = _get_installed_exts(ec, easyconfig_dep, processed_deps)

            # store the extensions of the dependencies of the current EasyConfig
            for ext in installed:
                ext_name, ext_version, ext_options = _get_extension_values(ext)
                ext_options['easyconfig_path'] = easyconfig_dep['spec']
                installed_exts.append((ext_name, ext_version, ext_options))

    # get and store the extensions of the current EasyConfig only if it is a dependency
    # avoid storing extensions of the original EasyConfig
    if ec_dep:
        for ext in _get_exts_list(ec_dep):
            ext_name, ext_version, ext_options = _get_extension_values(ext)
            ext_options['easyconfig_path'] = ec_dep['spec']
            installed_exts.append((ext_name, ext_version, ext_options))

    # restore the original value of the terse option
    update_build_option('terse', terse)

    return installed_exts


def update_exts_list(ecs):
    """
    Write a new EasyConfig recipe with all extensions in exts_list updated to the latest version.

    :param ecs: list of EasyConfig instances to complete dependencies for
    """

    for ec in ecs:

        # welcome message
        print_msg("\nUPDATING EASYCONFIG", prefix=False, log=_log)

        print_msg("Easyconfig: %s" % ec['spec'], log=_log)

        # get the extension list
        print_msg("Getting extension list...", log=_log)
        exts_list = _get_exts_list(ec)

        # get the extension's list class
        print_msg("Getting extension's list class...", log=_log)
        exts_defaultclass = _get_exts_list_class(ec)

        # get the Bioconductor version
        print_msg("Getting Bioconductor version (if any)...", log=_log)
        bioconductor_version = _get_bioconductor_version(ec)

        # get a new exts_list with all extensions to their latest version.
        print_msg("Updating extension list...", log=_log)
        updated_exts_list = _get_updated_exts_list(exts_list, exts_defaultclass, bioconductor_version)

        # get new easyconfig file with the updated extensions list
        print_msg('Updating Easyconfig instance...', log=_log)
        updated_easyconfig = _get_updated_easyconfig(ec, "exts_list", updated_exts_list)

        # back up the original easyconfig file
        ec_backup = back_up_file(ec['spec'], backup_extension='bak_update')
        print_msg("Backing up EasyConfig file at %s" % ec_backup, log=_log)

        # write the new easyconfig file
        print_msg('Writing updated EasyConfig file...', log=_log)
        write_file(ec['spec'], updated_easyconfig)

        # success message
        print_msg('EASYCONFIG SUCCESSFULLY UPDATED!\n', prefix=False, log=_log)


def check_installed_exts(ecs):
    """
    Print the list of exts_list extensions that are already being installed by dependencies or build dependencies

    :param ecs: list of EasyConfig instances to complete dependencies for
    """

    for ec in ecs:

        # welcome message
        print_msg("\nCHECK INSTALLED EXTENSIONS", prefix=False, log=_log)

        print_msg("Easyconfig: %s" % ec['spec'], log=_log)

        # get the extension list
        print_msg("Getting extension list...", log=_log)
        exts_list = _get_exts_list(ec)

        # get the extensions installed by dependencies
        print_msg("Getting extensions installed by dependencies or build dependencies...", log=_log)
        installed_exts = _get_installed_exts(ec)
        print_msg(f"\tInstalled extensions found: {len(installed_exts)}", prefix=False, log=_log)

        # cross-check the installed extensions with the exts_list
        print_msg("Checking installed extensions...", log=_log)
        _crosscheck_exts_list(exts_list, installed_exts)

        # success message
        print_msg('INSTALLED DEPENDENCY EXTENSIONS CHECKED!\n', prefix=False, log=_log)


def complete_exts_list(ecs):
    """
    Write a new EasyConfig recipie with the completed exts_list

    :param ecs: list of EasyConfig instances to complete dependencies for
    """

    for ec in ecs:

        # welcome message
        print_msg("\nCOMPLETE EASYCONFIG EXTENSIONS", prefix=False, log=_log)

        print_msg("Easyconfig: %s" % ec['spec'], log=_log)

        # get the extension list
        print_msg("Getting extension list: ", newline=False, log=_log)
        exts_list = _get_exts_list(ec)
        print_msg(f"{len(exts_list)} extensions found.", prefix=False, log=_log)

        # get the extension's list class
        print_msg("Getting extension's class: ", newline=False, log=_log)
        exts_defaultclass = _get_exts_list_class(ec)
        print_msg(f"{exts_defaultclass}", prefix=False, log=_log)

        # get the extensions installed by dependencies
        print_msg("Getting extensions installed by dependencies or build dependencies...", log=_log)
        installed_exts = _get_installed_exts(ec)
        print_msg(f"\tInstalled extensions found: {len(installed_exts)}", prefix=False, log=_log)

        # get the Bioconductor version
        print_msg("Getting Bioconductor version: ", newline=False, log=_log)
        bioconductor_version = _get_bioconductor_version(ec)
        print_msg(f"{'local_biocver not set. Bioconductor packages will not be considered' if not bioconductor_version else bioconductor_version}", prefix=False, log=_log)

        # get a new exts_list with all extensions to their latest version.
        print_msg("Searching for dependencies of the extensions...", log=_log)
        completed_exts_list = _get_completed_exts_list(
            exts_list, exts_defaultclass, installed_exts, bioconductor_version)

        # get new easyconfig file with the updated extensions list
        print_msg('Updating Easyconfig instance with completed exts_list...', log=_log)
        updated_easyconfig = _get_updated_easyconfig(ec, "exts_list", completed_exts_list)

        # back up the original easyconfig file
        ec_backup = back_up_file(ec['spec'], backup_extension='bak_update')
        print_msg("Backing up EasyConfig file at %s" % ec_backup, log=_log)

        # write the new easyconfig file
        print_msg('Writing updated EasyConfig file...', log=_log)
        write_file(ec['spec'], updated_easyconfig)

        # success message
        print_msg('EASYCONFIG SUCCESSFULLY COMPLETED!\n', prefix=False, log=_log)
