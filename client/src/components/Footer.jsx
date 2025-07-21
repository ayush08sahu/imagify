import React from 'react'
import { assets } from '../assets/assets'

const Footer = () => {
  return (
    <div className='flex item-center justify-between gap-4 py-3 mt-20'>
        <img src={assets.logo} alt="" width={150}/>
        <p className='flex-1 border-l border-gray-400 text-sm text-gray-500 max-sm:hidden text-center pt-3'>Copyright @AyushStack.dev | All rights reserved.</p>
        <div className='flex gap-2.5'>
            <a href="https://www.facebook.com/share/1Scumno2dc/" target="_blank">
              <img  src={assets.facebook_icon} alt="" width={35}/>
            </a>
            <a href="https://x.com/ayushsahu_08" target="_blank">
              <img src={assets.twitter_icon} alt="" width={35}/>
            </a>
            <a href="https://www.instagram.com/ig.ayush_xd/" target="_blank">
              <img src={assets.instagram_icon} alt="" width={35}/>
            </a>
        </div >
    </div>
  )
}

export default Footer