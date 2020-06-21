/* Copyright (C) 2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_BSIZE_H__
#define	__DETECT_BSIZE_H__

typedef struct DetectBsizeData {
    uint8_t mode;
    uint64_t lo;
    uint64_t hi;
} DetectBsizeData;

bool DetectBsizelenValidateContent(const Signature *s, int list, DetectBsizeData *bsz);//, const char **);
//void DetectBsizeApplyToContent(Signature *s, int list);
void DetectBsizeRegister(void);
int DetectBsizeMatch(const SigMatchCtx *ctx, const uint64_t buffer_size, bool eof);

#endif	/* __DETECT_URILEN_H__ */
