import tarfile
import os


def _safe_extract(tar, path=".", members=None):
    """Safely extract tar files by checking for path traversal attacks."""
    def _is_within_directory(directory, target):
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        prefix = os.path.commonprefix([abs_directory, abs_target])
        return prefix == abs_directory

    def _safe_members(tar, path):
        for member in tar.getmembers():
            member_path = os.path.join(path, member.name)
            if not _is_within_directory(path, member_path):
                raise Exception(f"Attempted path traversal in tar file: {member.name}")
            yield member

    if members is None:
        members = _safe_members(tar, path)
    tar.extractall(path, members=members)
