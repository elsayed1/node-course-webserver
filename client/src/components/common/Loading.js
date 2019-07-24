import React from 'react';
import LoadingImage from './loading.gif';
function Loading() {
  return (
    <div className='loading text-center'
    style={{
      height: '86vh'
    }}>
      <img 
      src={LoadingImage}
      width='400'
      height='400'
      alt='Loading... '/>
    </div>
  )
}
export default Loading;
