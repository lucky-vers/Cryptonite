# Sekai Forensics Report

So, no new forensics challenges for three weeks now, great.

I did some research on BTRFS for SIH. I found a blog post (https://mpdesouza.com/blog/btrfs-for-mere-mortals-inode-allocation/) that detailed how it stores inodes diffrently than any other filesystem.

The blog uses EXT4 as a point of comparison.

## Key Differences

1. **Inode Reporting**
   - EXT4 reports available inodes
   - Btrfs always reports 0 available inodes

2. **Space Allocation**
   - EXT4: Allocates entire disk on creation
   - Btrfs: Allocates structures dynamically

3. **Block Groups**
   - EXT4: Fixed block groups for data and metadata
   - Btrfs: Separate block groups for data and metadata, allocated on demand

4. **Inode Management**
   - EXT4: Uses fixed inode bitmaps
   - Btrfs: Allocates internal items dynamically

## EXT4 Characteristics

- Uses block groups to manage space
- Calculates maximum inodes based on disk size and inode ratio
- Reserves space for inode metadata in each block group

## Btrfs Characteristics

- Allocates block groups for data, metadata, and system separately
- Cannot predict maximum number of inodes
- Uses the same metadata space for various item types (INODE_ITEM, EXTENT_DATA, etc.)
- Subvolumes use the same inode numbers, but in different trees

## Conclusion

Btrfs's dynamic allocation makes it impossible to predict the maximum number of inodes, explaining why it always reports 0 available inodes when using tools like `df`.

The `btrfs-undelete` script asks us directly what the deleted file's name is, then scans the image for any files matching its name.

Since the easiest way to find out if a file has been deleted or not is for its inode to be `00`, and BTRFS doesn't do that, this gives us a challenge.

I'll research more on how to recover files without using inode metadata. Software such as UFS explorer already does that, so I might reverse engineer it..

